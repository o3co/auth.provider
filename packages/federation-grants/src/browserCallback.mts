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
 * `GET /callback/:connection`: the transaction spent before any code is exchanged,
 * the flow's checks asked before the exchange and again before the write, the code
 * exchanged, and the grant activated under the store's guard. Once the transaction
 * is spent, every outcome finishes the intent and returns the browser to the client.
 * An unknown transaction, one that could not be spent, and every failure after it
 * are audited as `federation.grant.authorization_failed`, an outage as
 * `temporarily_unavailable`.
 */

import {
	coveredByRevocationBoundary,
	type FederationGrantConnectTransaction,
	type FederationGrantIntent,
	type FederationGrantStore,
	federationGrantAuditMetadata,
	isFederationUpstreamOutage,
	judgeUpstreamAccessToken,
	parseScopeTokens,
} from "@o3co/auth-provider-core";
import type { RequestHandler } from "express";
import { accountHolds } from "./browserAccountBinding.mjs";
import { type CallbackError, clientReturn, plain } from "./browserAnswers.mjs";
import type {
	BrowserFlow,
	FederationGrantDelegatedAuthorizer,
	Unanswered,
} from "./browserFlow.mjs";
import { pinned, sessionHolds } from "./browserJudgement.mjs";
import { callbackParamsOf, claimOf, single } from "./browserRequest.mjs";
import { requestIdOf } from "./requestId.mjs";

/**
 * Where the upstream returns the browser. Query mode only: a `form_post` callback
 * arrives without the session cookie, so check 3 could not run; boot refuses
 * such a federation.
 *
 * Check 1's failures are a plain 400: there is nowhere trustworthy to send the
 * browser. Every later failure redirects to the intent's `redirect_uri` with the
 * client's `state`, the `grant_id` and one `CallbackError` code, never an
 * upstream's description, a thrown message or anything the callback carried.
 */
export function createCallbackHandler(flow: BrowserFlow): RequestHandler {
	const { options, now, log, admissionFor, auditFor, failed } = flow;
	return async (req, res) => {
		const correlationId = requestIdOf(res);
		const audit = auditFor(req);
		let transaction: FederationGrantConnectTransaction | null;
		try {
			const state = single(req.query.state);
			const connectionName = single(req.params.connection);
			if (state === undefined || connectionName === undefined) {
				plain(res, 400, "This request is not valid.");
				return;
			}
			// 1. The transaction: exists, names this connection, and is spent
			// HERE, before any code is exchanged — two callbacks cannot both
			// get as far as the upstream.
			try {
				transaction = await options.intentStore.consumeTransaction({
					state,
					connection: connectionName,
					now: now(),
				});
			} catch (error) {
				log.outage(
					"federation_grant_callback_unavailable",
					{
						correlationId,
						reason: "storage",
						store: "federation_grant_intent",
						step: "consume_transaction",
					},
					error,
				);
				// No transaction, so no flow to name: the audit carries this request alone.
				failed(req, res, "temporarily_unavailable");
				plain(res, 503, "Temporarily unavailable.");
				return;
			}
			if (transaction === null) {
				failed(req, res, "unknown_transaction");
				plain(res, 400, "This request has expired or has already been used. Start again.");
				return;
			}
		} catch (error) {
			log.unexpected("callback", { correlationId }, error);
			plain(res, 500, "Something went wrong.");
			return;
		}

		const { intent } = transaction;
		/** What this flow's events correlate by: the id its lodging carried. */
		const flowId = intent.correlationId;
		/** What every line of this callback carries: its grant, and THIS request's id. */
		const context = { grantId: intent.grantId, correlationId };
		/**
		 * What could not answer, behind the `temporarily_unavailable` redirect
		 * about to be sent: one line, at error.
		 */
		const outage = (unanswered: Unanswered): void =>
			log.outage(
				"federation_grant_callback_unavailable",
				{ ...context, reason: "storage", store: unanswered.store, step: unanswered.step },
				unanswered.error,
			);
		/** Every terminal outcome after check 1 ends here: the flow is over either way. */
		const finish = async (): Promise<void> => {
			try {
				await options.intentStore.finishIntent(intent.handle, now());
			} catch (error) {
				// Cannot undo anything, and the flow budget ends it regardless.
				log.degraded(
					"federation_grant_callback_step_failed",
					{ ...context, store: "federation_grant_intent", step: "finish_intent" },
					error,
				);
			}
		};
		/** `reason` is the audit's alone (`code/reason`); the client hears the code. */
		const fail = async (code: CallbackError, reason?: string): Promise<void> => {
			failed(req, res, reason === undefined ? code : `${code}/${reason}`, intent);
			await finish();
			res.redirect(303, clientReturn(intent, code));
		};

		try {
			const connection = options.connections.get(intent.connection);
			const at = now();

			// 2. Still the grant's current intent, within the flow's one deadline;
			// the configuration it was lodged against; and, for a renewal, the
			// grant it would renew still standing under the subject's boundary.
			let grantsBoundary: Date | null;
			let asking: Omit<Unanswered, "error"> = { store: "revocation_boundary", step: "read" };
			try {
				grantsBoundary = await readBoundary(options.grantsBoundary, intent.subject);
				asking = { store: "federation_grant", step: "is_current_intent" };
				if (!(await options.grantStore.isCurrentIntent(intent.grantId, intent.handle, at))) {
					await fail("grant_not_authorizable");
					return;
				}
			} catch (error) {
				outage({ ...asking, error });
				await fail("temporarily_unavailable");
				return;
			}
			if (!pinned(connection, intent)) {
				await fail("grant_not_authorizable");
				return;
			}
			if (intent.kind === "reauthorization") {
				const backstopped = await backstop(flow, intent, grantsBoundary, audit, flowId);
				if (backstopped !== "clear") {
					if (backstopped !== "revoked") outage(backstopped.unanswered);
					await fail(
						backstopped === "revoked" ? "grant_not_authorizable" : "temporarily_unavailable",
					);
					return;
				}
			}

			// 3. The browser the flow started in, still live, the intent's
			// subject's, and signed in after the subject's sessions boundary.
			// One claim for both reads: the re-read below admits the same one.
			const claim = claimOf(req);
			const admission = admissionFor(context);
			const session = await sessionHolds(admission, req, claim, transaction);
			if (session !== "ok") {
				await fail(session === "unavailable" ? "temporarily_unavailable" : session);
				return;
			}

			// 4. The upstream's own answer, validated by the adapter. A repeated parameter is
			// a malformed response (RFC 6749 §3.1): dropping copies could hand the adapter a
			// response without the `iss` it sent, so RFC 9207's check would hinge on metadata.
			if (Object.values(req.query).some((value) => typeof value !== "string")) {
				await fail("upstream_error");
				return;
			}
			const upstreamError = single(req.query.error);
			if (upstreamError !== undefined) {
				await fail(upstreamError === "access_denied" ? "access_denied" : "upstream_error");
				return;
			}
			const code = single(req.query.code);
			const authorizer = options.authorizerFor(intent.federation);
			if (code === undefined || authorizer === undefined || connection === undefined) {
				await fail("upstream_error");
				return;
			}
			const calledAt = now().getTime();
			let exchanged: Awaited<
				ReturnType<FederationGrantDelegatedAuthorizer["exchangeDelegatedCode"]>
			>;
			try {
				exchanged = await authorizer.exchangeDelegatedCode({
					code,
					codeVerifier: transaction.codeVerifier,
					redirectUri: intent.callbackUri,
					nonce: transaction.nonce,
					...(intent.resource === undefined ? {} : { resource: intent.resource }),
					callbackParams: callbackParamsOf(req),
					signal: AbortSignal.timeout(options.upstreamTimeoutMs),
					// Only the claims check 5 hands the Store, and none when it is not asked.
					identityClaims:
						options.identityLookup === "required" ? [...(connection.identityClaims ?? [])] : [],
				});
			} catch (error) {
				// Classified by what the error is, never its text (core's classifier).
				if (isFederationUpstreamOutage(error)) {
					// Not reached, or not in time: the outage the redirect says.
					log.outage(
						"federation_grant_callback_unavailable",
						{ ...context, reason: "upstream", step: "exchange" },
						error,
					);
					await fail("temporarily_unavailable");
				} else {
					// The upstream answered, and refused: its verdict, not an outage.
					log.degraded(
						"federation_grant_callback_exchange_refused",
						{ ...context, step: "exchange" },
						error,
					);
					await fail("upstream_error");
				}
				return;
			}
			const receivedAt = now().getTime();

			// 5. Account binding.
			const bound = await accountHolds(flow, intent, connection, exchanged.upstream);
			if (!bound.holds) {
				if (bound.unanswered !== undefined) outage(bound.unanswered);
				await fail(bound.code, bound.reason);
				return;
			}

			// 6. Eligibility: a refresh token, and an access token this provider may
			// disclose, judged on lifetime and type here and on scope in step 7, so each
			// failure names its own check.
			const tokens = exchanged.tokens;
			const refreshToken =
				typeof tokens.refreshToken === "string" && tokens.refreshToken.length > 0
					? tokens.refreshToken
					: undefined;
			if (refreshToken === undefined) {
				await fail("refresh_token_absent");
				return;
			}
			// Parsed by RFC 6749 §3.3's grammar (`parseScopeTokens`): a tab separates two
			// scopes rather than forming one the user was never shown. Omitted means as
			// requested; named but empty is judged in step 7.
			const scopeText = tokens.scope;
			const granted =
				scopeText === undefined
					? [...transaction.consent.scopes]
					: [...parseScopeTokens(scopeText)];
			const lifetime =
				typeof tokens.expiresIn === "number" &&
				Number.isFinite(tokens.expiresIn) &&
				tokens.expiresAt instanceof Date &&
				!Number.isNaN(tokens.expiresAt.getTime())
					? tokens.expiresIn
					: null;
			if (typeof tokens.accessToken !== "string" || tokens.accessToken.length === 0) {
				await fail("upstream_token_ineligible");
				return;
			}
			// The scope is judged in step 7 and given here as consented, so this
			// can only refuse for the lifetime or the token type.
			const judgement = judgeUpstreamAccessToken({
				issuedLifetime: lifetime,
				scopes: granted,
				consentedScopes: granted,
				maxAccessTokenLifetime: connection.maxAccessTokenLifetime,
				tokenType: typeof tokens.tokenType === "string" ? tokens.tokenType : "",
			});
			if (!judgement.eligible || lifetime === null) {
				await fail("upstream_token_ineligible");
				return;
			}

			// 7. Scope containment: an upstream that granted more than the user
			// was shown is refused, because a token cannot be narrowed after
			// the fact. Omitted means as requested (RFC 6749 §5.1); present and
			// empty is not an answer.
			if (scopeText !== undefined && granted.length === 0) {
				await fail("upstream_token_ineligible");
				return;
			}
			const shown = new Set(transaction.consent.scopes);
			if (!granted.every((scope) => shown.has(scope))) {
				await fail("scope_exceeded");
				return;
			}

			// The mandatory re-read, immediately before the write: a subject-wide revocation
			// may have landed during the upstream work. This narrows an attacker-controlled
			// window (hold the upstream redirect, finish the callback later) to the gap
			// between these reads and the activation; closing it needs write fencing.
			const again = await sessionHolds(admission, req, claim, transaction);
			if (again !== "ok") {
				await fail(again === "unavailable" ? "temporarily_unavailable" : again);
				return;
			}
			let reasking: Omit<Unanswered, "error"> = { store: "revocation_boundary", step: "read" };
			try {
				const boundaryNow = await readBoundary(options.grantsBoundary, intent.subject);
				reasking = { store: "federation_grant", step: "is_current_intent" };
				if (
					!(await options.grantStore.isCurrentIntent(intent.grantId, intent.handle, now())) ||
					coveredByRevocationBoundary(transaction.consent.at, boundaryNow, options.revocationSkewMs)
				) {
					await fail("grant_not_authorizable");
					return;
				}
			} catch (error) {
				outage({ ...reasking, error });
				await fail("temporarily_unavailable");
				return;
			}

			// 8. The guarded activation.
			const expiresAtMs = (tokens.expiresAt as Date).getTime();
			// When the token was obtained, on the adapter's clock, held inside the
			// window of the exchange — the retrieval's rule (retrieve.mts), so a
			// wild `expiresAt` can neither date a token in the future nor
			// lengthen its life.
			const obtainedAt = Math.min(Math.max(expiresAtMs - lifetime * 1000, calledAt), receivedAt);
			let written: Awaited<ReturnType<FederationGrantStore["activate"]>>;
			try {
				written = await options.grantStore.activate({
					grantId: intent.grantId,
					intentHandle: intent.handle,
					authorization: {
						identityRevision: intent.identityRevision,
						authorizationRevision: intent.authorizationRevision,
						upstream: { issuer: exchanged.upstream.issuer, subject: exchanged.upstream.subject },
						resource: intent.resource,
						scopes: granted,
						consent: {
							at: transaction.consent.at,
							sid: transaction.consent.sid,
							scopes: [...transaction.consent.scopes],
						},
						authorizedAt: now(),
						expiresAt: transaction.grantExpiresAt,
					},
					credentials: {
						refreshToken,
						accessToken: {
							value: tokens.accessToken,
							tokenType: tokens.tokenType as string,
							obtainedAt: new Date(obtainedAt),
							issuedLifetime: lifetime,
							scopes: granted,
						},
					},
					now: now(),
				});
			} catch (error) {
				outage({ store: "federation_grant", step: "activate", error });
				await fail("temporarily_unavailable");
				return;
			}
			if (!written.ok) {
				// The guard lost: superseded, revoked or expired in between. The
				// store says no more than that, and neither does this.
				await fail("grant_not_authorizable");
				return;
			}

			const grant = written.grant;
			if (intent.kind === "initial") {
				options.background.register(
					audit({
						type: "federation.grant.authorized",
						correlationId: flowId,
						grantId: grant.id,
						clientId: grant.clientId,
						subject: grant.subject,
						...federationGrantAuditMetadata(grant),
						outcome: bound.outcome,
					}).catch(() => undefined),
				);
			} else {
				options.background.register(
					audit({
						type: "federation.grant.reauthorized",
						correlationId: flowId,
						grantId: grant.id,
						clientId: grant.clientId,
						subject: grant.subject,
						...federationGrantAuditMetadata(grant),
						outcome: bound.outcome,
					}).catch(() => undefined),
				);
			}
			await finish();
			res.redirect(303, clientReturn(intent));
		} catch (error) {
			log.unexpected("callback", context, error);
			await fail("temporarily_unavailable");
		}
	};
}

/**
 * A renewal's backstop: the grant it would renew, compared with the subject's
 * GRANTS boundary. A hit is revoked durably (the one failure here meant to
 * change the record) and audited once, by whichever call wrote it.
 */
async function backstop(
	{ options, now }: BrowserFlow,
	intent: FederationGrantIntent,
	boundary: Date | null,
	audit: ReturnType<BrowserFlow["auditFor"]>,
	correlationId: string,
): Promise<"clear" | "revoked" | { readonly unanswered: Unanswered }> {
	let step = "find";
	try {
		const grant = await options.grantStore.find(intent.grantId, now());
		if (grant === null || grant.status === "revoked") return "revoked";
		if (grant.status === "pending") return "clear";
		if (!coveredByRevocationBoundary(grant.consent.at, boundary, options.revocationSkewMs)) {
			return "clear";
		}
		step = "revoke";
		const written = await options.grantStore.revoke(grant.id, "backstop", now());
		if (written.ok) {
			options.background.register(
				audit({
					type: "federation.grant.revoked",
					correlationId,
					grantId: written.grant.id,
					clientId: written.grant.clientId,
					subject: written.grant.subject,
					...federationGrantAuditMetadata(written.grant),
					outcome: "backstop",
				}).catch(() => undefined),
			);
		}
		return "revoked";
	} catch (error) {
		return { unanswered: { store: "federation_grant", step, error } };
	}
}

/** A boundary, or a refusal: an answer that is neither a date nor `null` is not "nothing revoked". */
async function readBoundary(
	read: (subject: string) => Promise<Date | null>,
	subject: string,
): Promise<Date | null> {
	const boundary = await read(subject);
	if (boundary !== null && !(boundary instanceof Date && !Number.isNaN(boundary.getTime()))) {
		throw new TypeError("the boundary is neither a date nor null");
	}
	return boundary;
}
