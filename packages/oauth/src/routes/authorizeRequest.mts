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
 * The request's shape: request objects, `response_mode`, single-valued
 * parameters, `claims`, `response_type`, PKCE, `nonce` and `scope`. Every refusal is on the
 * validated `redirect_uri`, and none costs a store or policy call.
 */

import {
	auditErrorList,
	type PublicClient,
	readSpaceDelimitedParameter,
} from "@o3co/auth-provider-core";
import {
	PKCE_METHOD_ABSENT_DEFAULT,
	PKCE_METHOD_S256,
	pkceMethodsForClient,
} from "../grants/pkce.mjs";
import { auditFailure, redirectError } from "./authorizeAnswers.mjs";
import { type AuthorizeContext, toStr } from "./authorizeContext.mjs";

/**
 * Refuses request objects (`request`, `request_uri`), which this server does
 * not implement, with OIDC Core's `request_not_supported` /
 * `request_uri_not_supported`. Ignoring them would be unsafe: the RP would
 * believe its signed, tamper-proof parameters were honoured while the
 * unsigned query was processed instead.
 */
export const checkRequestObjectUnsupported = (ctx: AuthorizeContext): boolean => {
	if (ctx.params.request !== undefined) {
		redirectError(
			ctx,
			"request_not_supported",
			"this authorization server does not accept request objects",
		);
		return false;
	}
	if (ctx.params.request_uri !== undefined) {
		redirectError(
			ctx,
			"request_uri_not_supported",
			"this authorization server does not accept request_uri",
		);
		return false;
	}
	return true;
};

/**
 * OAuth 2.0 Multiple Response Type Encoding Practices §2.1 `response_mode`:
 * only `query` is served (discovery's `response_modes_supported`), so any
 * other value, or a repeat, is refused with `invalid_request` rather than
 * answered in a mode the client did not ask for. An empty value is omitted
 * (RFC 6749 §3.1).
 */
export const checkResponseMode = (ctx: AuthorizeContext): boolean => {
	const raw = ctx.params.response_mode;
	if (raw === undefined || raw === "" || raw === "query") return true;
	redirectError(
		ctx,
		"invalid_request",
		typeof raw === "string"
			? `response_mode '${raw}' is not supported`
			: "response_mode must be a single string value",
	);
	return false;
};

/**
 * `/authorize` parameters RFC 6749 §3.1 defines as single-valued. Express
 * surfaces a repeat as an array, which every read here narrows to
 * `undefined` — absence. Unchecked, a repeated `code_challenge_method` would
 * downgrade to `plain`, a repeated `scope` would fall back to the default,
 * and a repeated `state` would be dropped, silently failing the client's
 * CSRF check.
 *
 * Deliberately absent: `response_type` (its own `unsupported_response_type`),
 * `response_mode` (`checkResponseMode` owns it), `resource` (repeatable, RFC 8707 §2), `client_id`/`redirect_uri` (checked
 * before a redirect target exists, so 400 JSON) and `nonce` (`checkNonce`
 * owns it). One owner per parameter.
 */
const SINGLE_VALUED_QUERY_PARAMS = [
	"scope",
	"state",
	"code_challenge",
	"code_challenge_method",
	"max_age",
	"acr_values",
	"reauth_ask",
	// One JSON object, read by `checkClaimsParameter`.
	"claims",
] as const;

/** Refuses a repeated single-valued parameter before any of it is interpreted. */
export const checkSingleValuedParams = (ctx: AuthorizeContext): boolean => {
	for (const name of SINGLE_VALUED_QUERY_PARAMS) {
		const value = ctx.params[name];
		if (value === undefined || typeof value === "string") continue;
		redirectError(ctx, "invalid_request", `${name} must be a single string value`);
		return false;
	}
	return true;
};

/**
 * OIDC Core §5.5 `claims`: a request naming `acr` (for id_token or userinfo,
 * essential or not) is refused with `invalid_request` — this server vouches
 * for `acr` only through `acr_values`, and ignoring the request would return
 * a token the RP reads as honouring it. Other uses of `claims` are ignored
 * (discovery omits `claims_parameter_supported`). An empty value is omitted
 * (RFC 6749 §3.1); any other non-object is malformed. Runs before the
 * re-authentication decision, so a refused request is never first sent to
 * log in.
 */
export const checkClaimsParameter = (ctx: AuthorizeContext): boolean => {
	const raw = ctx.params.claims;
	if (raw === undefined || raw === "") return true;
	let claims: unknown;
	try {
		claims = JSON.parse(raw as string);
	} catch {
		claims = undefined;
	}
	if (typeof claims !== "object" || claims === null || Array.isArray(claims)) {
		redirectError(ctx, "invalid_request", "claims is not a JSON object");
		return false;
	}
	const namesAcr = (member: unknown): boolean =>
		typeof member === "object" && member !== null && Object.hasOwn(member, "acr");
	const { id_token: idToken, userinfo } = claims as Record<string, unknown>;
	if (namesAcr(idToken) || namesAcr(userinfo)) {
		redirectError(ctx, "invalid_request", "request acr through acr_values");
		return false;
	}
	return true;
};

// Runs after the redirect target is validated, so the refusal redirects (RFC
// 6749 §4.1.2.1). Also refuses a repeat, which Express surfaces as an array.
export const checkResponseTypeIsCode = (ctx: AuthorizeContext): boolean => {
	const raw = ctx.params.response_type;
	if (toStr(raw) !== "code") {
		// Names what arrived: a missing and a repeated parameter are different
		// client bugs. Quoted with `'`, as `redirectError` holds the text to
		// RFC 6749's character set.
		const description =
			raw === undefined
				? "response_type is required"
				: Array.isArray(raw)
					? "response_type must not be included more than once"
					: `response_type '${String(raw)}' is not supported`;
		redirectError(ctx, "unsupported_response_type", description);
		return false;
	}
	return true;
};

/**
 * PKCE (OAuth 2.1 §4.1.1, RFC 9700 §2.1.1) for every client: a
 * `code_challenge` is required — confidential clients included, since a
 * client secret proves who redeems the code, not that the redeemer is the
 * party it was issued to — and the method is `S256` unless this client's
 * registration opts into `plain` (`pkceMethodsForClient`). Runs before the
 * policy hook so a bad method costs no external I/O.
 */
export const checkPkce = (
	ctx: AuthorizeContext,
	client: PublicClient,
	codeChallenge: unknown,
	codeChallengeMethod: unknown,
): { method: string } | null => {
	// The same resolved policy the authorization grant reads at `/token`. The
	// challenge is unconditionally required (`ResolvedPkceOptions.required` is
	// literally `true`).
	const policy = ctx.opts.oauth.pkce;
	if (typeof codeChallenge !== "string" || !codeChallenge) {
		redirectError(ctx, "invalid_request", "code_challenge is required");
		return null;
	}
	// A repeat was refused by `checkSingleValuedParams`, so undefined means
	// absent, which RFC 7636 §4.3 defines as `plain` — refused unless this
	// client opted in.
	const requestedMethod = toStr(codeChallengeMethod);
	const method = requestedMethod ?? PKCE_METHOD_ABSENT_DEFAULT;
	if (!pkceMethodsForClient(policy, client).includes(method)) {
		redirectError(
			ctx,
			"invalid_request",
			requestedMethod === undefined
				? `code_challenge_method is required and must be '${PKCE_METHOD_S256}'`
				: `code_challenge_method '${requestedMethod}' is not supported`,
		);
		return null;
	}
	return { method };
};

// Bounds `nonce`, which is stored on the code and echoed into the id_token,
// so an oversized value cannot exhaust memory or bloat tokens
// (`oauth.nonce.maxLength`). Runs after `redirect_uri` validation (so errors
// can redirect) and before the policy hook (so it costs no external I/O).
export const checkNonce = (ctx: AuthorizeContext): boolean => {
	const nonceMaxLength = ctx.opts.oauth.nonceMaxLength;
	if (ctx.params.nonce === undefined) return true;
	// The sole owner of the single-value rule for `nonce` (it is not in
	// SINGLE_VALUED_QUERY_PARAMS): a repeat arrives as an array and would
	// otherwise mint a code with no nonce, failing only later at the client.
	if (typeof ctx.params.nonce !== "string") {
		redirectError(ctx, "invalid_request", "nonce must be a single string value");
		return false;
	}
	const nonceValue = ctx.params.nonce;
	if (nonceValue.length > nonceMaxLength) {
		redirectError(ctx, "invalid_request", `nonce exceeds maximum length of ${nonceMaxLength}`);
		return false;
	}
	// Printable ASCII only (0x20-0x7E). Non-printable input could
	// confuse downstream JWT libraries that don't escape control
	// chars in JSON payloads. OIDC Core §3.1.2.1 leaves the
	// alphabet unconstrained; this is a defensive narrowing.
	if (!/^[\x20-\x7E]*$/.test(nonceValue)) {
		redirectError(ctx, "invalid_request", "nonce contains non-printable characters");
		return false;
	}
	return true;
};

/**
 * RFC 6749 §3.3 scope narrowing plus the openid requirement. Returns the
 * requested scopes and the allowlist-filtered set the policy step takes as
 * its ceiling, or `null` when a response has been sent.
 *
 * Scopes the client is not registered for are dropped (§3.3 allows it; the
 * token response's `scope` names what was granted). An omitted scope draws on
 * the declared `defaultScopes`, never the whole allowlist; with none declared
 * it is `invalid_scope`, except that a client with an empty allowlist keeps
 * the empty grant.
 */
export const resolveScopes = async (
	ctx: AuthorizeContext,
	scope: unknown,
	client: PublicClient,
): Promise<{ requestedScopes: string[]; allowedFilteredScopes: readonly string[] } | null> => {
	const allowedScopes = client.allowedScopes;
	// RFC 6749 §3.3, read strictly: narrowing (below) is the answer to a scope
	// this client may not have, and a malformed one is a different answer
	// (§4.1.2.1 `invalid_scope`) — `read\tbogus` is not the scope `read` with a
	// typo beside it. A repeat never reaches here (`checkSingleValuedParams`).
	const named = readSpaceDelimitedParameter(toStr(scope) ?? "");
	if (named === null) {
		redirectError(ctx, "invalid_scope", "scope is not a space-delimited list of scope-tokens");
		return null;
	}
	const requestedScopes = [...named];
	let allowedFilteredScopes: readonly string[];
	if (requestedScopes.length > 0) {
		allowedFilteredScopes = requestedScopes.filter((s) => allowedScopes.includes(s));
	} else if (client.defaultScopes !== undefined) {
		// Filtered even so: a custom ClientRepository is not schema-validated.
		allowedFilteredScopes = client.defaultScopes.filter((s) => allowedScopes.includes(s));
	} else if (allowedScopes.length === 0) {
		allowedFilteredScopes = [];
	} else {
		await auditFailure(ctx, { reason: "scope_omitted_without_default" });
		redirectError(ctx, "invalid_scope", "scope is required: this client declares no defaultScopes");
		return null;
	}
	// The router refuses a missing issuer, so `oidcMode` alone decides.
	if (
		ctx.opts.oauth.oidcMode === "oidc-required" &&
		// Both undermine "OIDC required": the request omits openid, or the
		// client allowlist filtered it out.
		(!requestedScopes.includes("openid") || !allowedFilteredScopes.includes("openid"))
	) {
		// The requested scopes are the caller's: logged as the first ten, each
		// capped, with the count when cut.
		const loggedScopes = auditErrorList(requestedScopes);
		ctx.opts.logger.warn(
			{
				clientId: ctx.clientId,
				requestedScopes: loggedScopes,
				...(loggedScopes.length < requestedScopes.length
					? { requestedScopeCount: requestedScopes.length }
					: {}),
				allowedFilteredScopes,
			},
			"authorize_rejected_missing_openid_scope",
		);
		redirectError(
			ctx,
			"invalid_scope",
			"openid scope is required when server is acting as an OIDC OP",
		);
		return null;
	}
	if (allowedFilteredScopes.length === 0 && requestedScopes.length > 0) {
		redirectError(ctx, "invalid_scope", "no requested scopes are allowed for this client");
		return null;
	}
	return { requestedScopes, allowedFilteredScopes };
};
