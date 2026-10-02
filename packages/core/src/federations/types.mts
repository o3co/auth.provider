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
 * The federation adapter port. An adapter implements `FederationProvider`
 * and, when it can do more, the capability interfaces below; the session
 * router drives them, `oauth` reads them off `federationProviders`, and
 * `federation-grants` delegates through them. It lives in core because those
 * packages may not import one another and all depend on core.
 *
 * What only the session router uses (`FederationResult`, its redirect policy)
 * stays in `@o3co/auth-provider-session`. The helpers an adapter builds its
 * requests with are beside this file: `pkce.mts`, `callback-url.mts`,
 * `client-secret.mts`, `token-snapshot.mts`.
 */

import type { FederationResponseMode } from "./response-mode.mjs";

/**
 * Snapshot of a successful federation callback: identity + OIDC-standard claims + OAuth 2 tokens.
 *
 * The `[key: string]: unknown` index signature is an extension slot for provider-specific claims
 * (Google `hd`, Microsoft `tid`, etc). Promote a claim to first-class only when it becomes
 * widely useful across providers (see Migration Guide in the spec).
 *
 * Fields are ordered to match the RFC 6749 §5.1 + OIDC Core §5.1 claim sources.
 */
export interface FederationProfile {
	/** IdP issuer URL (OIDC discovery `issuer`) or provider name for non-OIDC providers. */
	readonly issuer: string;
	/** OIDC `sub` claim — stable identifier for the federated user at this IdP. */
	readonly sub: string;
	readonly email?: string;
	readonly emailVerified?: boolean;
	readonly name?: string;
	readonly picture?: string;
	/** OAuth 2 access token for subsequent IdP API calls. */
	readonly accessToken?: string;
	/** Refresh token; absent if the IdP did not issue one. */
	readonly refreshToken?: string;
	/** OIDC id_token JWT, if issued. */
	readonly idToken?: string;
	/**
	 * Absolute expiry time of `accessToken`, derived from `expires_in` by the adapter.
	 *
	 * `null` means the provider did not issue a finite expiry (e.g. GitHub OAuth Apps
	 * classic tokens). Consumers MUST treat `null` as "do not attempt refresh; reuse
	 * until the provider explicitly invalidates". Required (no `undefined`) so adapters
	 * are forced to make an explicit decision per provider rather than the route layer
	 * inventing a fallback expiry.
	 */
	readonly expiresAt: Date | null;
	/**
	 * `expires_in` from the token response, in seconds, as the adapter's
	 * library read it (openid-client applies `parseFloat` to a non-number);
	 * `null` when it carried none. A rule that judges the lifetime a token was
	 * ISSUED with reads this, not a difference of dates: one clock step turns
	 * 3600 into 3601. Optional; an adapter may omit it.
	 */
	readonly expiresIn?: number | null;
	/** `scope` as the token response carried it, space-delimited (RFC 6749 §5.1). Absent when it carried none. */
	readonly scope?: string;
	/** `token_type` as the adapter's library reports it — oauth4webapi lower-cases it. */
	readonly tokenType?: string;
	/** Provider-specific extension claims (e.g. Google `hd`, Microsoft `tid`). */
	readonly [key: string]: unknown;
}

/**
 * Pure-function interface for an upstream OAuth 2 / OIDC identity provider.
 *
 * Implementations MUST NOT expose vendor library types (passport, arctic,
 * openid-client, etc.) through this interface or types exported beside it.
 *
 * State (CSRF `state`, PKCE `codeVerifier`) is managed by the session route
 * layer and passed into both calls; providers never allocate state.
 */
export interface FederationProvider {
	readonly name: string;
	readonly scope: readonly string[];

	/**
	 * How this IdP delivers the authorization response: `"query"` (the
	 * default, also for an absent or unrecognised value) or `"form_post"`.
	 *
	 * `"form_post"` changes three things in the route layer and nothing in the
	 * adapter:
	 *
	 * 1. the start route appends `response_mode=form_post` to the URL
	 *    `buildAuthorizationUrl` returned;
	 * 2. `POST /session/oauth/federation/<name>/callback` accepts a form body,
	 *    with the same state / PKCE / nonce binding as the GET callback (a
	 *    provider without the mode answers 405 there);
	 * 3. the flow's ephemeral state moves into a federation transaction with a
	 *    dedicated cookie, because the cross-site POST callback does not carry
	 *    the session cookie. See {@link FederationResponseMode}.
	 */
	readonly responseMode?: FederationResponseMode;

	/**
	 * Build the authorization URL for the RFC 6749 §4.1 + RFC 7636 code flow.
	 *
	 * `codeVerifier` is a cryptographically strong URL-safe random string the
	 * route layer stores before calling. Adapters derive `code_challenge` with
	 * `codeChallenge(codeVerifier)` (`pkce.mts`) and never accept a
	 * pre-computed challenge, so the transform methods cannot mismatch.
	 *
	 * OIDC providers MUST forward `nonce` as the upstream `nonce` parameter so
	 * `exchangeCode`'s `expectedNonce` check binds the id_token to this session
	 * (OIDC Core §3.1.3.7). OAuth-only providers ignore it.
	 */
	buildAuthorizationUrl(params: {
		readonly redirectUri: string;
		readonly state: string;
		readonly codeVerifier: string;
		readonly nonce?: string;
	}): URL;

	/**
	 * Exchange an authorization `code` for a normalized `FederationProfile`,
	 * which MUST include `issuer` and `sub`. Adapters post to the token
	 * endpoint and may call UserInfo.
	 *
	 * OIDC providers MUST pass `nonce` as the library's `expectedNonce` so the
	 * id_token's nonce is checked against the session's (OIDC Core §3.1.3.7).
	 * OAuth-only providers ignore it.
	 */
	exchangeCode(params: {
		readonly code: string;
		readonly codeVerifier: string;
		readonly redirectUri: string;
		readonly nonce?: string;
		/**
		 * The rest of the callback's parameters (query string for `"query"`,
		 * form body for `"form_post"`), string values only.
		 *
		 * `code` and `state` are excluded: the route binds both (`code` arrives
		 * above, `state` was checked against the session), so an adapter cannot
		 * read either from an unvalidated copy.
		 *
		 * Carries identity data an IdP returns beside the token response (Apple
		 * sends the user's name once, in a `user` JSON field, never in the
		 * id_token) and protocol parameters: `iss` (RFC 9207) goes to the
		 * library's issuer check through `callbackUrlForExchange`, so narrowing
		 * the bag would switch that check off.
		 *
		 * **Relayed through the user agent and unsigned.** The `state` check
		 * binds them to this session and nothing more: treat them as
		 * self-asserted. What `mapClaims` makes of them stays under
		 * `claims.federated[<provider>]`, subject to the promotion rules
		 * (`federations/claim-precedence.mts` in `@o3co/auth-provider-session`),
		 * never an authorization input.
		 */
		readonly callbackParams?: Readonly<Record<string, string>>;
	}): Promise<FederationProfile>;
}

/**
 * Arguments for an OIDC RP-Initiated Logout (end-session) request.
 */
export interface EndSessionRequest {
	idTokenHint?: string;
	/**
	 * Where the browser goes after the upstream logout. **A caller passes only
	 * a validated URI**: one that exactly matched a `postLogoutRedirectUris`
	 * entry of the client asking for the logout (OIDC RP-Initiated Logout 1.0
	 * §3) and passes `checkRedirectUri` (a custom `ClientRepository` may hold
	 * one that does not), or `undefined`. Never the request's raw
	 * `post_logout_redirect_uri`.
	 *
	 * Adapters treat it as a trusted redirect target: without an end-session
	 * endpoint, the bundled Google, GitHub and Apple adapters redirect to it
	 * directly, so an unchecked value would be an open redirect on the
	 * provider's origin.
	 */
	postLogoutRedirectUri?: string;
	state?: string;
}

export interface EndSessionResult {
	url: URL;
	method: "GET";
}

export interface SupportsLogout {
	endSession(req: EndSessionRequest): Promise<EndSessionResult>;
}

export function supportsLogout(
	provider: FederationProvider | undefined | null,
): provider is FederationProvider & SupportsLogout {
	if (provider == null) return false;
	return typeof (provider as { endSession?: unknown }).endSession === "function";
}

/**
 * What an adapter's `mapClaims` answers of an upstream profile. The session
 * package's claim precedence promotes a string `email`, `name` or `picture`
 * the local `User` leaves absent, and records the whole map under the
 * session's `claims.federated[<provider>]`, a custom claim. So every value
 * must be JSON data — a string, a finite number, a boolean, `null`, or a
 * list or plain object of those — as a login's custom claims must be
 * (`PasswordLoginFacts.claims`). A declared claim of another type is not
 * promoted.
 */
export interface MappedClaims {
	readonly email?: string;
	readonly emailVerified?: boolean;
	readonly name?: string;
	readonly picture?: string;
	readonly groups?: ReadonlyArray<string>;
	readonly [key: string]: unknown;
}

export interface SupportsClaimMapping {
	mapClaims(profile: FederationProfile): MappedClaims;
}

export function supportsClaimMapping(
	p: FederationProvider | undefined | null,
): p is FederationProvider & SupportsClaimMapping {
	if (p == null) return false;
	return typeof (p as { mapClaims?: unknown }).mapClaims === "function";
}

/**
 * Partial token snapshot returned by `SupportsRefresh.refreshToken`.
 *
 * `issuer` and `sub` are optional: the refresh grant does not re-assert
 * identity, so callers reuse the stored one. Other fields mean what they do
 * on `FederationProfile`. They are named rather than derived with `Omit`,
 * which over a string index signature keeps only the signature and lets a
 * wrongly typed field through.
 */
export interface RefreshedTokens {
	readonly issuer?: string;
	readonly sub?: string;
	readonly email?: string;
	readonly emailVerified?: boolean;
	readonly name?: string;
	readonly picture?: string;
	readonly accessToken?: string;
	readonly refreshToken?: string;
	readonly idToken?: string;
	readonly expiresAt?: Date | null;
	readonly expiresIn?: number | null;
	readonly scope?: string;
	readonly tokenType?: string;
	readonly [key: string]: unknown;
}

export interface SupportsRefresh {
	/** Refresh an upstream IdP access token using its refresh token. Returns a partial token snapshot. */
	refreshToken(refreshToken: string): Promise<RefreshedTokens>;
}

export function supportsRefresh(
	p: FederationProvider | undefined | null,
): p is FederationProvider & SupportsRefresh {
	if (p == null) return false;
	return typeof (p as { refreshToken?: unknown }).refreshToken === "function";
}

/**
 * What a delegated authorization asks of an adapter: the URL a user is sent
 * to so that a client may hold the upstream's tokens without a session.
 * Unlike the login flow's `buildAuthorizationUrl`, the scopes are the
 * intent's and not the adapter's, the nonce is required, and a resource
 * indicator (RFC 8707) and an operator's extra parameters may come along.
 */
export interface DelegatedAuthorizationRequest {
	readonly redirectUri: string;
	readonly state: string;
	readonly codeVerifier: string;
	/** Required: the id_token that comes back is bound to it (OIDC Core §3.1.3.7). */
	readonly nonce: string;
	/** The intent's scopes, which core has already held to the connection's ceiling. */
	readonly scopes: readonly string[];
	/** Sent as the RFC 8707 `resource` parameter. */
	readonly resource?: string;
	/**
	 * The connection's extra parameters, e.g. Google's `access_type=offline`.
	 * An adapter refuses any that would take over a parameter it owns — the
	 * client, the response type, the callback, the state, the PKCE challenge,
	 * the nonce, the scopes, the resource, a request object, the response mode.
	 */
	readonly authorizationParams?: Readonly<Record<string, string>>;
}

export interface DelegatedRefreshRequest {
	readonly refreshToken: string;
	/** The grant's scopes: RFC 6749 §6 lets a refresh ask for no more than was granted. */
	readonly scopes?: readonly string[];
	/** The resource the grant was authorized for; an upstream that needs it at authorization needs it here too. */
	readonly resource?: string;
	/** Aborts the upstream request. */
	readonly signal?: AbortSignal;
}

/**
 * What a delegated refresh answers; the capability returns it and
 * `../federation-grants/retrieve.mts` consumes it. Every field is optional:
 * an answer the library refused to parse may still carry a rotated refresh
 * token, which must never be lost, so `{ refreshToken }` alone is valid, and
 * core treats an answer without a usable access token as
 * `malformed_token_response`.
 */
export interface DelegatedTokens {
	readonly accessToken?: string;
	/** Absent when the upstream did not rotate it (RFC 6749 §6). */
	readonly refreshToken?: string;
	/**
	 * Seconds, exactly as the upstream issued them; `null` when it named none.
	 * This is what a grant's eligibility judges, and it cannot be recovered from
	 * `expiresAt`: one step of the clock between the adapter and the consumer
	 * turns 3600 into 3601, which starves every grant on a connection whose
	 * maximum is 3600.
	 */
	readonly expiresIn?: number | null;
	/**
	 * The adapter's own `now + expiresIn`; `null` when the upstream named no
	 * lifetime. Read with `expiresIn` by `readUpstreamTokenLifetime`: the
	 * earlier of the two ends the token, so neither can lengthen it.
	 */
	readonly expiresAt?: Date | null;
	/**
	 * Space-delimited, as in the token response. Absent means the scope the
	 * request already carried — for a refresh, the grant's (RFC 6749 §6).
	 */
	readonly scope?: string;
	/** As the library reports it — lower-cased by oauth4webapi. */
	readonly tokenType?: string;
}

/**
 * The authorization parameters a delegated adapter owns, which an operator's
 * `authorizationParams` may therefore not set. An exclusion rather than an
 * allowlist: vendors keep inventing parameters, and the ones that matter are
 * those this provider computes (PKCE challenge, state, nonce, the redirect
 * the callback is checked against). Setting those from configuration would
 * take over the flow's security parameters.
 *
 * The adapter refuses these when building the URL, and the federation-grant
 * routes refuse them at boot, before a user reaches a consent page.
 */
export const RESERVED_DELEGATED_AUTHORIZATION_PARAMS: ReadonlySet<string> = new Set([
	"client_id",
	"response_type",
	"redirect_uri",
	"state",
	"code_challenge",
	"code_challenge_method",
	"nonce",
	"scope",
	"resource",
	"request",
	"request_uri",
	"response_mode",
]);

/**
 * What the connect callback asks of an adapter: exchange the returned code for
 * the grant's first tokens, and say whose they are.
 *
 * Separate from `exchangeCode`, which answers a login profile (it may call
 * UserInfo, map claims, fill a lifetime the upstream never sent) and has no
 * place for the RFC 8707 `resource` at the token endpoint, the lifetime the
 * upstream SENT, or a per-call abort signal for the callback's time budget.
 */
export interface DelegatedCodeExchangeRequest {
	readonly code: string;
	readonly codeVerifier: string;
	/** The connection's `callbackURL`, exactly as the authorization request sent it. */
	readonly redirectUri: string;
	/** Required: the id_token is bound to it (OIDC Core §3.1.3.7). */
	readonly nonce: string;
	/** Sent at the token endpoint too (RFC 8707 §2.2). */
	readonly resource?: string;
	/**
	 * The rest of the callback's parameters, as for `exchangeCode`: `code` and
	 * `state` excluded, `iss` (RFC 9207) forwarded to the mix-up check.
	 */
	readonly callbackParams?: Readonly<Record<string, string>>;
	/** Aborts the upstream request. */
	readonly signal?: AbortSignal;
	/**
	 * The id_token claims to carry beside the subject: what a Store matches a
	 * person on across registrations where `sub` is pairwise, such as Entra's
	 * `tid` and `oid`. A local allowlist, never sent upstream. Omitted means
	 * none. Names are checked by {@link identityClaimsProblem}.
	 */
	readonly identityClaims?: readonly string[];
}

/**
 * The id_token claims {@link DelegatedCodeExchangeRequest.identityClaims} may
 * not name: the protocol's own bindings and the token's and session's
 * identifiers, which are the adapter's to check and say nothing stable about
 * who a person is — and the names that would reach an object's prototype.
 */
export const RESERVED_IDENTITY_CLAIMS: ReadonlySet<string> = new Set([
	"sub",
	"iss",
	"aud",
	"azp",
	"nonce",
	"exp",
	"iat",
	"nbf",
	"auth_time",
	"at_hash",
	"c_hash",
	"s_hash",
	"jti",
	// Entra's token identifier — its `jti` by another name.
	"uti",
	"sid",
	"__proto__",
	"constructor",
	"prototype",
]);

const IDENTITY_CLAIM_NAME = /^[\x21-\x7E]{1,256}$/;

/**
 * Why `names` is not a usable `identityClaims` list, or `undefined` when it
 * is. Case-sensitive names of printable ASCII without spaces, none
 * reserved, none repeated — refused rather than trimmed or de-duplicated,
 * because a list an operator wrote wrongly is a list they meant differently.
 * Shared by the adapter, which refuses at the point of use, and the grant
 * routes, which refuse at boot.
 */
export function identityClaimsProblem(names: readonly unknown[]): string | undefined {
	const seen = new Set<string>();
	for (const name of names) {
		if (typeof name !== "string" || !IDENTITY_CLAIM_NAME.test(name)) {
			return `identityClaims: ${JSON.stringify(name)} is not a claim name (printable ASCII, no spaces)`;
		}
		if (RESERVED_IDENTITY_CLAIMS.has(name)) {
			return `identityClaims: "${name}" is a claim the protocol owns, not an identity to match on`;
		}
		if (seen.has(name)) return `identityClaims: "${name}" is listed twice`;
		seen.add(name);
	}
	return undefined;
}

/**
 * The claims asked for, out of a VERIFIED id_token's: own properties
 * only, non-empty strings only, nothing coerced. A claim absent or of another
 * type is left out rather than failed on here — the caller knows which ones
 * it cannot do without.
 */
export function selectIdentityClaims(
	claims: Readonly<Record<string, unknown>>,
	names: readonly string[],
): Readonly<Record<string, string>> {
	const selected: Record<string, string> = {};
	for (const name of names) {
		if (!Object.hasOwn(claims, name)) continue;
		const value = claims[name];
		if (typeof value === "string" && value.length > 0) selected[name] = value;
	}
	return selected;
}

/**
 * The grant's first tokens and whose they are. `upstream` comes from an
 * id_token the adapter VERIFIED — signature, issuer, audience, expiry, nonce,
 * and `at_hash` where present — and from nothing else: not UserInfo, not an
 * email. An exchange whose identity could not be verified throws, and salvages
 * nothing: unlike a refresh, it has no authorization a refresh token could be
 * kept under.
 */
export interface DelegatedAuthorizationResult {
	/**
	 * `claims` holds the {@link DelegatedCodeExchangeRequest.identityClaims}
	 * the verified id_token carried as non-empty strings — possibly fewer than
	 * were asked for, always a fresh object, empty when none were asked for.
	 */
	readonly upstream: {
		readonly issuer: string;
		readonly subject: string;
		readonly claims: Readonly<Record<string, string>>;
	};
	/** As a delegated refresh answers them: `{ refreshToken }` alone when the lifetime was not one. */
	readonly tokens: DelegatedTokens;
}

/**
 * The capability behind federation grants: an adapter that can send a user to
 * authorize a delegation, exchange the returned code for the grant's first
 * tokens, and refresh them without a session. Detected by ALL THREE methods
 * being present; an adapter with only some is refused at boot by name rather
 * than failing at a callback with a user waiting.
 */
export interface SupportsDelegatedAuthorization {
	buildDelegatedAuthorizationUrl(params: DelegatedAuthorizationRequest): URL;
	exchangeDelegatedCode(
		params: DelegatedCodeExchangeRequest,
	): Promise<DelegatedAuthorizationResult>;
	refreshDelegatedToken(params: DelegatedRefreshRequest): Promise<DelegatedTokens>;
}

export function supportsDelegatedAuthorization(
	p: FederationProvider | undefined | null,
): p is FederationProvider & SupportsDelegatedAuthorization {
	if (p == null) return false;
	const candidate = p as {
		buildDelegatedAuthorizationUrl?: unknown;
		exchangeDelegatedCode?: unknown;
		refreshDelegatedToken?: unknown;
	};
	return (
		typeof candidate.buildDelegatedAuthorizationUrl === "function" &&
		typeof candidate.exchangeDelegatedCode === "function" &&
		typeof candidate.refreshDelegatedToken === "function"
	);
}
