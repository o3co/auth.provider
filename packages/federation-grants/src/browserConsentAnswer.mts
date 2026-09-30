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
 * `POST /consent`: the answer, held to the deployment's `csrfGuard` before the
 * session binding, the challenge or the intent store is read, re-read through the
 * pending consent, and recorded under the exact binding. A denial returns the
 * browser to the client; a refused or malformed answer spends no consent.
 */

import type { CsrfVerdict, FederationGrantIntentStore } from "@o3co/auth-provider-core";
import type { RequestHandler } from "express";
import { clientReturn, jsonError, NO_PENDING } from "./browserAnswers.mjs";
import type { BrowserFlow } from "./browserFlow.mjs";
import { pendingFor } from "./browserPendingConsent.mjs";
import { requestIdOf } from "./requestId.mjs";

/**
 * Why the consent answer was refused: the `csrfGuard`'s reason, or
 * `unrecognized` for a verdict outside its contract.
 */
type CsrfRefusalReason = Extract<CsrfVerdict, { outcome: "refused" }>["reason"] | "unrecognized";

/** The consent answer's `error_description` for each {@link CsrfRefusalReason}. */
const CSRF_REFUSAL: Readonly<Record<CsrfRefusalReason, string>> = Object.freeze({
	foreign_origin: "cross-site answer refused",
	token_absent: "no origin and no valid csrf token",
	token_invalid: "no origin and no valid csrf token",
	unrecognized: "cross-site answer refused",
});

/**
 * The guard's verdict read fail-closed: `null` for an acceptance, otherwise
 * why not. Only `{ outcome: "accepted" }` accepts; a promise, another outcome
 * or an unknown reason refuses, and a promise's rejection is handled here.
 */
function csrfRefusal(verdict: unknown): CsrfRefusalReason | null {
	const read = verdict as { readonly outcome?: unknown; readonly reason?: unknown } | null;
	if (typeof (verdict as { then?: unknown } | null)?.then === "function") {
		(verdict as PromiseLike<unknown>).then(undefined, () => undefined);
		return "unrecognized";
	}
	if (read?.outcome === "accepted") return null;
	const reason = read?.outcome === "refused" ? read.reason : undefined;
	return typeof reason === "string" && Object.hasOwn(CSRF_REFUSAL, reason)
		? (reason as CsrfRefusalReason)
		: "unrecognized";
}

/** `POST /consent`: the user's answer. */
export function createConsentAnswerHandler(flow: BrowserFlow): RequestHandler {
	const { options, now, randomId, log, failed } = flow;
	return async (req, res) => {
		try {
			// Asked before the route reads the session binding, the challenge or
			// the intent store, so a refused answer spends no consent.
			const refusal = csrfRefusal(options.csrfGuard.check(req));
			if (refusal !== null) {
				log.refused("federation_grant_consent_csrf_refused", {
					reason: refusal,
					correlationId: requestIdOf(res),
					origin: req.get("origin"),
				});
				jsonError(res, 403, "invalid_request", CSRF_REFUSAL[refusal]);
				return;
			}
			const body = (req.body ?? {}) as Record<string, unknown>;
			const found = await pendingFor(flow, req, res, body.challenge);
			if (found === null) return;
			const { intent, binding, challenge } = found;
			/** What every line of this answer carries. */
			const context = {
				method: req.method,
				grantId: intent.grantId,
				correlationId: requestIdOf(res),
			};
			/** A `503` this answer gives: one line at error. */
			const consentUnavailable = (
				description: "storage" | "upstream_unavailable",
				at: { readonly store?: string; readonly step: string; readonly refusal?: string },
				...cause: [] | [unknown]
			): void => {
				log.outage(
					"federation_grant_consent_unavailable",
					{ ...context, reason: description, ...at },
					...cause,
				);
				jsonError(res, 503, "temporarily_unavailable", description);
			};
			/**
			 * The answer recorded, or `null` after a `503`: an intent store that
			 * cannot record it is its outage, not an unexpected error.
			 */
			const record = async (
				answer: Parameters<FederationGrantIntentStore["answerConsent"]>[0]["answer"],
			) => {
				try {
					return await options.intentStore.answerConsent({
						challenge,
						binding,
						answer,
						now: now(),
					});
				} catch (error) {
					consentUnavailable(
						"storage",
						{ store: "federation_grant_intent", step: "answer_consent" },
						error,
					);
					return null;
				}
			};
			const decision = body.decision;
			if (decision !== "accept" && decision !== "deny") {
				// Refused with the question still parked: nothing was answered.
				jsonError(res, 400, "invalid_request", "decision must be 'accept' or 'deny'");
				return;
			}

			if (decision === "deny") {
				const answered = await record({ decision: "deny" });
				if (answered === null) return;
				if (answered.outcome !== "denied") {
					jsonError(res, 400, "invalid_request", NO_PENDING);
					return;
				}
				if (intent.kind === "reauthorization") {
					// Only this renewal's pointer, never a newer one: a refusal for
					// a superseded intent must not end the intent that replaced it.
					try {
						await options.grantStore.retireIntent({
							grantId: intent.grantId,
							handle: intent.handle,
							now: now(),
						});
					} catch (error) {
						// The consent is already spent, so nothing can activate
						// through this pointer; it lapses with the flow budget.
						log.degraded(
							"federation_grant_consent_step_failed",
							{ ...context, store: "federation_grant", step: "retire_intent" },
							error,
						);
					}
				}
				failed(req, res, "access_denied", intent);
				res.redirect(303, clientReturn(intent, "access_denied"));
				return;
			}

			const authorizer = options.authorizerFor(intent.federation);
			if (authorizer === undefined) {
				// Boot refuses a connection whose federation lacks the
				// capability; reaching here is a composition fault, and nothing
				// has been spent.
				consentUnavailable("upstream_unavailable", { step: "authorizer" });
				return;
			}
			const state = randomId();
			const nonce = randomId();
			const codeVerifier = randomId();
			let upstream: URL;
			try {
				// Built BEFORE the answer is spent: a configuration fault in the
				// URL must not consume the user's consent.
				upstream = authorizer.buildDelegatedAuthorizationUrl({
					redirectUri: intent.callbackUri,
					state,
					codeVerifier,
					nonce,
					scopes: intent.scopes,
					...(intent.resource === undefined ? {} : { resource: intent.resource }),
					authorizationParams: intent.authorizationParams,
				});
			} catch (error) {
				consentUnavailable("upstream_unavailable", { step: "authorization_url" }, error);
				return;
			}
			const answered = await record({ decision: "accept", state, codeVerifier, nonce });
			if (answered === null) return;
			if (answered.outcome === "refused") {
				// A fault on this side, and nothing was thrown: the store names it.
				consentUnavailable("storage", {
					store: "federation_grant_intent",
					step: "answer_consent",
					refusal: answered.reason,
				});
				return;
			}
			if (answered.outcome !== "accepted") {
				jsonError(res, 400, "invalid_request", NO_PENDING);
				return;
			}
			// No transaction-store outage can reach this line: the redirect
			// upstream happens only once the transaction exists.
			res.redirect(303, upstream.href);
		} catch (error) {
			log.unexpected("consent", { method: req.method, correlationId: requestIdOf(res) }, error);
			jsonError(res, 500, "server_error", "unexpected_error");
		}
	};
}
