/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * The callback's state check, its security boundary: the ephemeral state read
 * from where the start kept it, `state` compared with it, and the state
 * retired before any async work. A request with no `state`, or a wrong
 * one, leaves the transaction in place: it is spent only once `state`
 * matches.
 */

import {
	type FederationProvider,
	type Logger,
	resolveFederationResponseMode,
} from "@o3co/auth-provider-core";
import type { Request, Response } from "express";
import type {
	FederationTransactionEnvelope,
	FederationTransactionStore,
} from "../federations/transaction.mjs";
import { abandonCookieSession, SESSION_STORE_UNAVAILABLE } from "../internal/cookieSession.mjs";
import { readCookie } from "../internal/cookies.mjs";
import type { FederationRouterContext } from "./FederationContext.mjs";
import {
	type FederationStoreStep,
	logCleanupFailed,
	logStoreUnavailable,
} from "./FederationLog.mjs";

/**
 * Read, check and retire the callback's ephemeral state. Answers and
 * returns `null` on a refusal or an outage; otherwise returns the envelope,
 * already retired.
 */
export const consumeCallbackState = async (
	ctx: FederationRouterContext,
	provider: FederationProvider,
	params: Readonly<Record<string, string>>,
	req: Request,
	res: Response,
	log: Logger,
): Promise<FederationTransactionEnvelope | null> => {
	const { transactionStore, transactionCookieName, clearTransactionCookie } = ctx;

	const responseMode = resolveFederationResponseMode(provider);

	// Where the ephemeral state lives: a `"query"` federation's in the
	// session (its callback is a same-site top-level GET carrying the
	// session cookie); a `"form_post"` federation's in a transaction record
	// addressed by its own cookie, because a cross-site POST does not carry
	// a `SameSite=Lax` session cookie. Without that cookie the callback is
	// refused before `state` is read, so a stolen `state` alone is worthless.
	let fed: FederationTransactionEnvelope | undefined;
	let transactions: FederationTransactionStore | undefined;
	let transactionId: string | undefined;

	/**
	 * Consume the transaction (cookie and record). Answers a failed delete as
	 * `ok: false` rather than throwing, so a refusal path can clean up best
	 * effort while irreversible work fails closed. The outcome is carried by
	 * `ok`, never by the cause: a store may reject with any value, `undefined`
	 * included. A no-op for a `"query"` federation.
	 */
	const consumeTransaction = async (): Promise<
		{ readonly ok: true } | { readonly ok: false; readonly cause: unknown }
	> => {
		if (!transactions || transactionId === undefined) return { ok: true };
		clearTransactionCookie(provider, res);
		const id = transactionId;
		transactionId = undefined;
		try {
			await transactions.delete(id);
			return { ok: true };
		} catch (cause) {
			return { ok: false, cause };
		}
	};

	/**
	 * Consume the transaction on a path that is refusing anyway: a failed
	 * delete is one `federation_cleanup_failed` warn, and the request's
	 * cookie session is dropped so express-session does not write to that
	 * store again.
	 */
	const discardTransaction = async (): Promise<void> => {
		const discarded = await consumeTransaction();
		if (!discarded.ok) {
			logCleanupFailed(log, "federation_transaction", "delete", discarded.cause);
			abandonCookieSession(req);
		}
	};

	/**
	 * The cookie session's store (or a transaction in it) could not answer:
	 * log the outage first, then optionally discard the transaction (so a
	 * cleanup warn never precedes its cause), drop the cookie session, and
	 * answer `503`.
	 */
	const refuseCookieStoreOutage = async (
		store: "cookie_session" | "federation_transaction",
		step: FederationStoreStep,
		cause: unknown,
		{ discard = false }: { readonly discard?: boolean } = {},
	): Promise<unknown> => {
		logStoreUnavailable(log, "federation_callback_store_unavailable", store, step, cause);
		if (discard) await discardTransaction();
		abandonCookieSession(req);
		return res.status(503).json(SESSION_STORE_UNAVAILABLE);
	};

	if (responseMode === "form_post") {
		transactions = transactionStore(req);
		transactionId = readCookie(req, transactionCookieName(provider));
		if (!transactions || transactionId === undefined || transactionId.length === 0) {
			// No transaction cookie, no transaction. This is the refusal an
			// attacker replaying a `state` from another browser meets.
			clearTransactionCookie(provider, res);
			res.status(400).json({
				error: "invalid_session",
				error_description: "No active federation session for this provider",
			});
			return null;
		}
		try {
			fed = (await transactions.get(transactionId)) ?? undefined;
		} catch (err) {
			await refuseCookieStoreOutage("federation_transaction", "get", err, { discard: true });
			return null;
		}
	} else {
		fed = req.session.federation;
	}

	// Check the envelope is present and names this provider
	if (!fed || fed.name !== String(req.params.name)) {
		await discardTransaction();
		res.status(400).json({
			error: "invalid_session",
			error_description: "No active federation session for this provider",
		});
		return null;
	}

	// The ephemeral state is spent only once `state` matches. A request
	// with no `state`, or a wrong one, is refused and leaves it in place, in
	// both modes: the `form_post` transaction cookie is `SameSite=None`, so
	// it rides any cross-site request (an `<img>` GET or an auto-submitted
	// form included), and a `query` federation's `SameSite=Lax` session
	// cookie rides a top-level cross-site GET. Such a request leaves the
	// state in place, so the flow in progress still completes. Any number of
	// mismatches against a 128-bit CSPRNG `state` leaves a match no more
	// likely.
	if (typeof params.state !== "string" || params.state.length === 0) {
		res.status(400).json({
			error: "invalid_request",
			error_description: "Missing state parameter",
		});
		return null;
	}

	// CSRF state check — unchanged, and deliberately so: the transaction
	// cookie is an addition to this comparison, never a replacement for it.
	if (params.state !== fed.state) {
		res.status(400).json({
			error: "invalid_state",
			error_description: "CSRF state mismatch",
		});
		return null;
	}

	// Retire the ephemeral state BEFORE any async work, so a replay arriving
	// after this callback finds nothing — including when `exchangeCode` throws.

	// Retirement is a read then a delete: the express-session Store API has
	// no atomic read-and-consume. A callback after an earlier one's delete
	// is refused (a replayed `code`/`state`, the back button, a retry), but
	// overlapping callbacks can both reach `exchangeCode`
	// (`Federation.transactionConcurrency.test.mts` pins this). The IdP
	// bounds that: an authorization code is single-use, and PKCE binds it to
	// the verifier in the record. A dedicated atomic store would need its
	// own component slot in every deployment, for a property the IdP already
	// provides. If the state cannot be retired at all, fail closed (503): a
	// forced delete failure plus a replay would otherwise face no reuse check.
	if (responseMode === "form_post") {
		const consumed = await consumeTransaction();
		if (!consumed.ok) {
			await refuseCookieStoreOutage("federation_transaction", "delete", consumed.cause);
			return null;
		}
	} else {
		delete req.session.federation;
		const reusePrevSaveErr = await new Promise<unknown>((resolve) => {
			req.session.save((err) => resolve(err ?? null));
		});
		if (reusePrevSaveErr) {
			await refuseCookieStoreOutage("cookie_session", "save", reusePrevSaveErr);
			return null;
		}
	}

	return fed;
};
