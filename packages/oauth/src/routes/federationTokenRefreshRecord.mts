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
 * What a refresh the upstream answered ends in: an answer that cannot be read
 * as a token, or whose type may not be handed on, is refused, while a rotated
 * refresh token is still kept, best effort; otherwise the refreshed record is
 * written and its token answered. A record with no finite expiry, refreshed
 * because it holds a refresh token, keeps answering its stored token when the
 * answer's lifetime is refused, as it did before it was due. Every write lands only on the record the
 * refresh was made from, and a stored token is answered only from it; a
 * refresh whose record was removed or rewritten meanwhile is dropped, never
 * written over what replaced it. No token is answered after the upstream call
 * unless the caller's session is still live when it is answered: a close that
 * committed meanwhile removes the stored tokens itself.
 */

import { canonicalScope, emitAuditEvent, loggableError } from "@o3co/auth-provider-core";
import type { Response } from "express";
import type { FederationTokenCaller, FederationTokenContext } from "./federationTokenContext.mjs";
import { isDisclosable, refuseUndisclosableTokenType } from "./federationTokenDisclosure.mjs";
import {
	answerDiscardedRefresh,
	answerIfChanged,
	replaceRecord,
	type StoredRecord,
} from "./federationTokenRecord.mjs";
import { narrowedScope, type RefreshReading } from "./federationTokenRefreshAnswer.mjs";
import { stampRefreshFailed } from "./federationTokenRefreshFailure.mjs";
import { checkSessionLive } from "./federationTokenSession.mjs";
import { answerToken } from "./federationTokenSuccess.mjs";

/**
 * The refusals of an answer, then steps 11f and 11h. `current` is the record
 * the refresh was made from.
 */
export const recordRefresh = async (
	ctx: FederationTokenContext,
	caller: FederationTokenCaller,
	current: StoredRecord,
	reading: RefreshReading,
): Promise<Response> => {
	const { opts, req, res, federation, logger, storeUnavailable } = ctx;
	const { sub } = caller;
	const currentTokens = current.value;
	const {
		accessToken,
		rotatedRefreshToken,
		rotatedIdToken,
		lifetime,
		tokenTypeIsBroken,
		nextTokenType,
	} = reading;

	/**
	 * Keeps a rotated refresh token even when this refresh brought
	 * nothing that can be handed on: the upstream invalidated the old one
	 * (RFC 6749 §6), so dropping it would strand the connection until
	 * re-consent. Best effort, logged as `federation_token_keep_rotated_*`;
	 * the route still answers its refusal, not a 503. Kept only on the record
	 * the refresh was made from: a record removed since (a logout) or
	 * rewritten since (a relink, or another refresh) is left as it is, since
	 * an equal refresh token does not make it the same connection, and that
	 * outcome is returned so the refusal is answered as a dropped refresh.
	 * `updated` once kept; `undefined` when nothing was written.
	 */
	const keepRotatedRefreshToken = async (): Promise<
		"updated" | "missing" | "conflict" | undefined
	> => {
		if (rotatedRefreshToken !== undefined && rotatedRefreshToken !== currentTokens.refreshToken) {
			try {
				const outcome = await replaceRecord(ctx, caller, current, {
					...currentTokens,
					refreshToken: rotatedRefreshToken,
					// Rotated alongside it, and worth the same: the stored
					// `id_token` is what logout sends as `id_token_hint`.
					idToken: rotatedIdToken ?? currentTokens.idToken,
				});
				if (outcome !== "updated") {
					logger.warn(
						{
							federation,
							store: "federation_token",
							reason: outcome === "missing" ? "record_gone" : "replaced_concurrently",
						},
						"federation_token_keep_rotated_skipped",
					);
				}
				return outcome;
			} catch (error) {
				logger.warn(
					{ federation, store: "federation_token", step: "replace_if", err: loggableError(error) },
					"federation_token_keep_rotated_failed",
				);
			}
		}
		return undefined;
	};

	// The adapter answered something this route cannot read as a token.
	if (accessToken === undefined || !lifetime.accepted || tokenTypeIsBroken) {
		const kept = await keepRotatedRefreshToken();
		if (kept === "missing" || kept === "conflict") return answerDiscardedRefresh(ctx, caller, kept);
		const servesStored = !lifetime.accepted && currentTokens.expiresAt === null;
		// The stored token is handed on only from the record the refresh was
		// made from; a kept rotation already confirmed it by its write.
		if (servesStored && kept !== "updated") {
			const changed = await answerIfChanged(ctx, caller, current);
			if (changed !== null) return changed;
		}
		emitAuditEvent(opts.auditSink, {
			timestamp: new Date(),
			type: "federation.token.refresh_failed",
			subject: sub ?? undefined,
			ip: req.ip,
			userAgent: req.get("user-agent"),
			// The lifetime's verdict tells an upstream's garbage from a getter that threw.
			details: !lifetime.accepted
				? { federation, reason: "invalid_expiry", verdict: lifetime.verdict }
				: {
						federation,
						reason: accessToken === undefined ? "no_access_token" : "invalid_token_type",
					},
		});
		if (servesStored) {
			if (!isDisclosable(currentTokens)) {
				return refuseUndisclosableTokenType(ctx, caller, currentTokens.tokenType);
			}
			if (!(await checkSessionLive(ctx, caller))) return res;
			return answerToken(ctx, caller, currentTokens, false);
		}
		stampRefreshFailed(ctx, caller, current);
		return res.status(500).json({
			error: "refresh_failed",
			error_description: "federation token refresh failed",
		});
	}

	// 11f: the refreshed record, falling back to the post-lock
	// snapshot for fields the IdP did not rotate. The expiry comes only
	// from this answer (`lifetime`, always a finite end): the stored one
	// belongs to the expired token, and copying it forward would refresh on
	// every request.
	const updatedTokens = {
		accessToken,
		refreshToken: rotatedRefreshToken ?? currentTokens.refreshToken,
		// IdPs like Google/GitHub typically return no new id_token on refresh;
		// keep the stored one, which logout sends as `id_token_hint`.
		idToken: rotatedIdToken ?? currentTokens.idToken,
		expiresAt: lifetime.expiresAt,
		// What the upstream last named, else what the record carried; judged
		// below, before the write, so the write and the response agree.
		tokenType: nextTokenType,
		// The three readings and the bound they are judged against are
		// `narrowedScope`'s, next to its own reasoning. Nothing about the
		// rule is restated here, so the two cannot drift apart.
		scope: narrowedScope(reading.answeredScope, currentTokens.scope, currentTokens.grantedScope),
		// The ceiling itself never moves: a refresh is bounded by the grant,
		// not by the token it replaces (RFC 6749 §6). Parsed on the way back
		// out as well — it came from a store, and a store is another thing
		// this route does not own.
		grantedScope: canonicalScope(currentTokens.grantedScope),
		// From this answer alone, like the expiry: the stored one dates the
		// token being replaced. `undefined` for an end stated only as an instant.
		obtainedAt: lifetime.obtainedAt,
	};

	// The refresh worked but its token may not be handed on. Keep the
	// rotated refresh token so fixing the upstream needs no re-consent.
	if (!isDisclosable(updatedTokens)) {
		const kept = await keepRotatedRefreshToken();
		if (kept === "missing" || kept === "conflict") return answerDiscardedRefresh(ctx, caller, kept);
		return refuseUndisclosableTokenType(ctx, caller, nextTokenType);
	}

	let outcome: Awaited<ReturnType<typeof replaceRecord>>;
	try {
		outcome = await replaceRecord(ctx, caller, current, updatedTokens);
	} catch (error) {
		storeUnavailable(federation, "federation_token", "replace_if", error);
		return res.status(503).json({
			error: "temporarily_unavailable",
			error_description: "federation token store unavailable",
		});
	}
	// Removed or rewritten since it was read: this refresh's tokens belong to a
	// connection that is gone, and are neither stored nor handed on.
	if (outcome !== "updated") return answerDiscardedRefresh(ctx, caller, outcome);

	if (!(await checkSessionLive(ctx, caller))) return res;

	// 11h: `updatedTokens`, not the adapter's object: the answer was read
	// once, and a getter read a second time may answer differently from what
	// was just written to the store.
	return answerToken(ctx, caller, updatedTokens, true);
};
