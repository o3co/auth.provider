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
 * Consent for a client that is not first-party: the user's recorded consent
 * covers the request, or the request is parked under a session-bound challenge
 * and sent to the consent page. A store outage is `temporarily_unavailable`.
 */

import {
	type ConsentStore,
	consentCovers,
	loggableError,
	type PublicClient,
} from "@o3co/auth-provider-core";
import type { Request } from "express";
import { auditFailure, redirectError } from "./authorizeAnswers.mjs";
import type { PromptDirective } from "./authorizeAsk.mjs";
import {
	type AuthorizeContext,
	authorizeRequestUrl,
	withoutConsentPrompt,
} from "./authorizeContext.mjs";
import { newConsentChallenge, PENDING_CONSENT_TTL_MS } from "./consent.mjs";

/** The end-user the session names, or `null` when it names nobody. */
const subjectOf = (req: Request): string | null => {
	const id = req.session?.user?.id;
	return typeof id === "string" && id.length > 0 ? id : null;
};

/**
 * The authorize request to resume after consent: this request less
 * `prompt=consent` (`withoutConsentPrompt`), which the round trip answers.
 */
const resumeUrl = (ctx: AuthorizeContext): string =>
	withoutConsentPrompt(authorizeRequestUrl(ctx.issuerOrigin, ctx.req)).toString();

/**
 * Consent for a client that is not an explicit `firstParty: true`. Without
 * it, a forced navigation from an attacker's page would make a logged-in
 * victim's browser mint a code for the attacker's chosen `code_challenge`.
 * The user is asked on the deployment's own page and the answer recorded, so
 * covered requests are not asked again. Runs after every request-shape check
 * (no consent for a request that would fail anyway) and before the policy.
 */
export const checkConsent = async (
	ctx: AuthorizeContext,
	client: PublicClient,
	scopes: readonly string[],
	prompt: PromptDirective,
): Promise<boolean> => {
	if (client.firstParty === true) return true;
	const store = ctx.opts.consentStore;
	const pendingStore = ctx.opts.pendingConsentStore;
	if (store === undefined || pendingStore === undefined) {
		await auditFailure(ctx, { reason: "client_not_first_party" });
		redirectError(
			ctx,
			"unauthorized_client",
			"client is not authorized for the authorization endpoint",
		);
		return false;
	}
	const sub = subjectOf(ctx.req);
	if (sub === null) {
		await auditFailure(ctx, { reason: "consent_without_subject" });
		redirectError(ctx, "access_denied", "the session names no subject to ask for consent");
		return false;
	}
	let record: Awaited<ReturnType<ConsentStore["find"]>>;
	try {
		record = await store.find(sub, ctx.clientId);
	} catch (err) {
		// An outage is not a decision either way: neither a code nor a refusal
		// the user could act on. The same rule the session-liveness read applies.
		ctx.opts.logger.error(
			{ err: loggableError(err), clientId: ctx.clientId },
			"authorize_consent_store_unavailable",
		);
		redirectError(ctx, "temporarily_unavailable", "consent store unavailable");
		return false;
	}
	if (!prompt.consent && consentCovers(record, scopes)) return true;
	if (prompt.silent) {
		// OIDC Core §3.1.2.6: no interaction was permitted, and interaction is
		// what is needed.
		await auditFailure(ctx, { reason: "consent_required" });
		redirectError(
			ctx,
			"consent_required",
			"prompt=none was requested but the end-user has not consented to this client",
		);
		return false;
	}
	// Park the request under an unguessable, session-bound challenge: the
	// consent page's answer must carry it back, which keeps a forged cross-site
	// POST from answering for the user. Parked in its own record, not on the
	// session (a per-request snapshot), so it can be consumed atomically.
	const sessionId = (ctx.req as { sessionID?: unknown }).sessionID;
	if (typeof sessionId !== "string" || sessionId.length === 0) {
		await auditFailure(ctx, { reason: "consent_without_session_id" });
		redirectError(ctx, "access_denied", "the session has no id to bind the consent request to");
		return false;
	}
	const challenge = newConsentChallenge();
	const createdAt = Date.now();
	try {
		await pendingStore.set({
			challenge,
			sessionId,
			sub,
			clientId: ctx.clientId,
			scopes: [...scopes],
			grantedScopes: record === null ? [] : [...record.scopes],
			authorizeUrl: resumeUrl(ctx),
			redirectUri: ctx.redirectUri,
			state: ctx.state,
			createdAt,
			expiresAt: createdAt + PENDING_CONSENT_TTL_MS,
		});
	} catch (err) {
		// The same rule as the consent-store read above: an outage is not a
		// decision either way.
		ctx.opts.logger.error(
			{ err: loggableError(err), clientId: ctx.clientId },
			"authorize_pending_consent_store_unavailable",
		);
		redirectError(ctx, "temporarily_unavailable", "consent store unavailable");
		return false;
	}
	// `oauth.consentPage.url` may already carry a query string, like the
	// login URL.
	const consentUrl = ctx.opts.consentUrl();
	const joiner = consentUrl.includes("?") ? "&" : "?";
	ctx.res.redirect(`${consentUrl}${joiner}challenge=${encodeURIComponent(challenge)}`);
	return false;
};
