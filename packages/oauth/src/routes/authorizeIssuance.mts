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
 * Issuing the code (RFC 6749 §4.1.2): the audience it carries (RFC 8707 §2),
 * the code record, which alone carries the identity binding and how the
 * session had authenticated when the code was issued (`acr`, `amr`), and the
 * redirect that delivers it with `state` and the `authorize.granted` audit
 * event.
 */

import {
	type CodeRepository,
	deriveAudienceFromResources,
	emitAuditEvent,
	loggableError,
	type PublicClient,
	type UserSession,
	unrepresentedResources,
	vouchedAmr,
} from "@o3co/auth-provider-core";
import type { Response } from "express";
import { authorizationResponseUrl } from "./authorizationResponse.mjs";
import { redirectError } from "./authorizeAnswers.mjs";
import type { AuthorizeContext } from "./authorizeContext.mjs";

/**
 * RFC 8707 §2 audience shaping for the code record, or `null` when the
 * requested resources cannot be represented and a response has been sent.
 */
export const resolveAudienceForPersist = (
	ctx: AuthorizeContext,
	client: PublicClient,
	authorizeResource: readonly string[] | null,
	grantedAudience: readonly string[] | undefined,
): { audienceForPersist: readonly string[] | undefined } | null => {
	// RFC 8707 §2: when a `resource` was requested and no policy narrowed an
	// audience, derive it here, so the audience persisted on the code — which
	// `/token` enforces — is decided exactly once. Bounded by the client's
	// `allowedAudiences` plus its id.
	let effectiveGrantedAudience = grantedAudience;
	if (ctx.opts.oauth.resourceIndicatorEnabled && authorizeResource && !effectiveGrantedAudience) {
		const derived = deriveAudienceFromResources(
			authorizeResource,
			new Set([...(client.allowedAudiences ?? []), ctx.clientId]),
		);
		if (derived !== undefined) effectiveGrantedAudience = [derived];
	}
	const audienceForPersist =
		effectiveGrantedAudience && effectiveGrantedAudience.length > 0
			? effectiveGrantedAudience
			: undefined;

	// RFC 8707 §2: refuse now rather than issue a code `/token` would reject
	// after the user completed the redirect. Mirrors the token endpoint's
	// audience: the persisted one, else the client id.
	if (ctx.opts.oauth.resourceIndicatorEnabled && authorizeResource) {
		const effectiveAudience = audienceForPersist?.[0] ?? ctx.clientId;
		const unrepresented = unrepresentedResources(authorizeResource, effectiveAudience);
		if (unrepresented.length > 0) {
			redirectError(
				ctx,
				"invalid_target",
				`requested_resources_not_in_audience: ${unrepresented.join(" ")}`,
			);
			return null;
		}
	}
	return { audienceForPersist };
};

/**
 * RFC 6749 §4.1.2 code issuance, or `null` after a `temporarily_unavailable`
 * redirect: a code store that cannot answer is the condition §4.1.2.1 names
 * `temporarily_unavailable` for, not `server_error`. Logged once at error
 * level as `authorize_store_unavailable`.
 */
export const mintCode = async (
	ctx: AuthorizeContext,
	params: {
		codeChallenge: string | undefined;
		codeChallengeMethod: string | undefined;
		grantedScope: readonly string[] | undefined;
		grantedAudience: readonly string[] | undefined;
		/** The `acr` the session met. */
		acr: string | undefined;
		/** The record admission admitted the request on; `null` without a user-session store. */
		session: UserSession | null;
	},
): Promise<{ code: string } | null> => {
	let issue: Awaited<ReturnType<CodeRepository["createCode"]>>;
	try {
		issue = await ctx.opts.codeRepository.createCode({
			client_id: ctx.clientId, // the identity binding lives on the code record
			redirect_uri: ctx.redirectUri, // required: RFC 6749 §4.1.3 compares it at the token endpoint
			code_challenge: params.codeChallenge,
			code_challenge_method: params.codeChallengeMethod,
			grantedScope: params.grantedScope,
			grantedAudience: params.grantedAudience,
			// OIDC round-trip state.
			nonce: typeof ctx.params.nonce === "string" ? ctx.params.nonce : undefined,
			sid: typeof ctx.req.session?.sid === "string" ? ctx.req.session.sid : undefined,
			acr: params.acr,
			// Decided here, as `acr` is: what the admitted session vouches for
			// now. `/token` stamps it, so a step-up recorded after this does
			// not reach the code's tokens.
			amr: params.session === null ? undefined : vouchedAmr(params.session),
		});
	} catch (err) {
		ctx.opts.logger.error(
			{
				store: "authorization_code",
				step: "create",
				clientId: ctx.clientId,
				err: loggableError(err),
			},
			"authorize_store_unavailable",
		);
		redirectError(ctx, "temporarily_unavailable", "authorization code store unavailable");
		return null;
	}
	return { code: issue.code };
};

// The code record alone carries the identity binding — no session writes, so
// concurrent requests sharing a session cannot race. `consumeByCode`'s atomic
// read-and-delete is the sole authenticity gate.
export const redirectWithCode = async (ctx: AuthorizeContext, code: string): Promise<Response> => {
	const location = authorizationResponseUrl(
		ctx.redirectUri,
		{ code },
		ctx.state,
		ctx.opts.authorizationResponseIssuer,
	);

	await emitAuditEvent(ctx.opts.auditSink, {
		timestamp: new Date(),
		type: "authorize.granted",
		subject: typeof ctx.req.session.user?.id === "string" ? ctx.req.session.user.id : undefined,
		clientId: ctx.clientId,
		ip: ctx.req.ip,
		userAgent: ctx.req.get("user-agent"),
		details: { response_type: "code" },
	});
	return ctx.res.redirect(location) as unknown as Response;
};
