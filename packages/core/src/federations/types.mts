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
 * The federation adapter port (#626 P1).
 *
 * An adapter implements `FederationProvider` and, when it can do more, the
 * capability interfaces below; the session router drives them, `oauth` reads
 * them off `federationProviders`, and `federation-grants` delegates through
 * them. It lives in core because every one of those is a different package
 * and none of them may import another: the contract a contribution is
 * registered with has to be the one its consumer reads, and core is the only
 * place all of them already depend on.
 *
 * What stays in `@o3co/auth-provider-session` is what only its router uses:
 * `FederationResult`, the redirect policy it feeds, and the routes
 * themselves. The pure helpers an adapter builds its requests with — the
 * PKCE challenge, the code-exchange URL, the client-secret resolver — are
 * beside this contract, in `pkce.mts`, `callback-url.mts` and
 * `client-secret.mts`.
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
	 * library read it (openid-client applies `parseFloat` to one that is not a
	 * number); `null` when it carried none. `expiresAt` above is derived from
	 * it on the adapter's clock, and one step of that clock is enough to turn
	 * 3600 into 3601 — so a rule that judges the lifetime a token was ISSUED
	 * with reads this, not the difference of two dates (#593, D5). Optional:
	 * adapters written before it may omit it.
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
 * Implementations MUST NOT expose vendor library types (passport, arctic, openid-client, etc)
 * through this interface or through types exported alongside it. Adapters should keep vendor
 * concerns below a ≤50-line facade (target).
 *
 * State (CSRF `state`, PKCE `codeVerifier`) is managed by the session route layer and passed
 * into both calls; providers never allocate state themselves.
 */
export interface FederationProvider {
	readonly name: string;
	readonly scope: readonly string[];

	/**
	 * How this IdP delivers the authorization response — `"query"` (the
	 * default, and what every federation written before Sign in with Apple
	 * assumed) or `"form_post"`.
	 *
	 * Declaring `"form_post"` changes three things in the route layer, and
	 * nothing in the adapter:
	 *
	 * 1. the start route appends `response_mode=form_post` to the URL this
	 *    provider's `buildAuthorizationUrl` returned, so the parameter is
	 *    written once for every federation instead of in each adapter;
	 * 2. `POST /session/oauth/federation/<name>/callback` starts accepting an
	 *    `application/x-www-form-urlencoded` body, with the same state / PKCE
	 *    / nonce binding as the GET callback (a provider that does not declare
	 *    the mode answers 405 there, so no existing federation gains a POST
	 *    surface);
	 * 3. this federation's ephemeral state moves out of the session and into a
	 *    federation transaction — an opaque id in a dedicated `HttpOnly;
	 *    Secure; SameSite=None` cookie, path-scoped to the callback, and the
	 *    envelope in a store record keyed by it — because the callback arrives
	 *    as a cross-site POST that the session cookie does not accompany. The
	 *    application session cookie is left exactly as configured; see
	 *    `federations/transaction.mts` in `@o3co/auth-provider-session` (#494).
	 *
	 * Optional, and an unrecognised value is read as the default: absence must
	 * mean "query" for every provider that predates this field.
	 */
	readonly responseMode?: FederationResponseMode;

	/**
	 * Build the authorization URL for RFC 6749 §4.1 + RFC 7636 code flow.
	 *
	 * `codeVerifier` MUST be a cryptographically strong URL-safe random string; the route
	 * layer generates and stores it in the session before calling. Adapters compute
	 * `code_challenge` with this package's `codeChallenge(codeVerifier)` (`pkce.mts`); do
	 * not accept a pre-computed challenge to avoid mismatches between transform methods.
	 *
	 * `nonce` is optional — OIDC providers MUST forward it as the upstream `nonce`
	 * authorization param so that the matching `expectedNonce` check in `exchangeCode`
	 * binds the returned id_token to this session (OIDC Core §3.1.3.7). OAuth-only
	 * providers (e.g. GitHub OAuth Apps) ignore it.
	 */
	buildAuthorizationUrl(params: {
		readonly redirectUri: string;
		readonly state: string;
		readonly codeVerifier: string;
		readonly nonce?: string;
	}): URL;

	/**
	 * Exchange an authorization `code` for a normalized `FederationProfile`.
	 *
	 * Adapters post to the IdP's token endpoint, optionally call the userinfo endpoint,
	 * and return a `FederationProfile`. They MUST include `issuer` and `sub`; all other
	 * standard fields are optional.
	 *
	 * `nonce` is optional — OIDC providers MUST pass it as `expectedNonce` to the
	 * upstream library so that the id_token nonce claim is verified against the
	 * session-stored value (OIDC Core §3.1.3.7). OAuth-only providers ignore it.
	 */
	exchangeCode(params: {
		readonly code: string;
		readonly codeVerifier: string;
		readonly redirectUri: string;
		readonly nonce?: string;
		/**
		 * The rest of the callback's parameters — query string for a `"query"`
		 * federation, form body for a `"form_post"` one — with only the string
		 * values kept.
		 *
		 * **`code` and `state` are excluded.** Both are the framework's to bind,
		 * and both are already accounted for: `code` arrives in its own field
		 * above, and `state` is the value the route compared against the session
		 * before calling. Leaving them in would put each in two places, one of
		 * which the route validated and one of which it did not — so an adapter
		 * cannot read a credential from the wrong one, because the wrong one is
		 * not there.
		 *
		 * Present so an IdP that returns identity data *beside* the token
		 * response can be adapted without a second callback contract: Apple
		 * sends the end user's name exactly once, in a `user` JSON field on the
		 * first authorization, and never in the id_token.
		 *
		 * Protocol response parameters travel here as well. An adapter forwards
		 * `iss` (RFC 9207) from this bag to its library's issuer check — through
		 * this package's `callbackUrlForExchange` (`callback-url.mts`), so that
		 * the rule lives in one place (#595, #597) — and narrowing the bag to
		 * identity data would silently switch that check off.
		 *
		 * **These values are relayed through the user agent and are not signed.**
		 * The `state` check binds them to this session, which is all it binds:
		 * an adapter must treat anything read here as self-asserted, and the
		 * route layer keeps whatever `mapClaims` makes of it under
		 * `claims.federated[<provider>]` subject to the ordinary promotion
		 * rules (see `federations/claim-precedence.mts` in
		 * `@o3co/auth-provider-session`) — never as an authorization input.
		 */
		readonly callbackParams?: Readonly<Record<string, string>>;
	}): Promise<FederationProfile>;
}

/**
 * Arguments for an OIDC RP-Initiated Logout (end-session) request. Unchanged from v0.3.x.
 */
export interface EndSessionRequest {
	idTokenHint?: string;
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
 * `issuer` and `sub` are optional because callers reuse the stored identity from the
 * original federation profile — the refresh grant does not re-assert identity. All other
 * token fields follow the same semantics as `FederationProfile`.
 *
 * The fields are named rather than derived from `FederationProfile`: `Omit`
 * over a type with a string index signature keeps only the index signature,
 * and a snapshot with an access token that was a number type-checked. Every
 * field is optional, so a snapshot of `{ issuer, sub }` still passes; a wrong
 * type on a named field does not, which it should never have.
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
 * What a delegated authorization asks of an adapter (#593, D17): the URL a
 * user is sent to so that a client may hold the upstream's tokens without a
 * session. Unlike the login flow's `buildAuthorizationUrl`, the scopes are the
 * intent's and not the adapter's, the nonce is required, and a resource
 * indicator (RFC 8707) and an operator's extra parameters may come along.
 */
export interface DelegatedAuthorizationRequest {
	readonly redirectUri: string;
	readonly state: string;
	readonly codeVerifier: string;
	/** Required: the id_token that comes back is bound to it (OIDC Core §3.1.3.7). */
	readonly nonce: string;
	/** The intent's scopes (D6), which core has already held to the connection's ceiling. */
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
	/** The grant's scopes (D5): RFC 6749 §6 lets a refresh ask for no more than was granted. */
	readonly scopes?: readonly string[];
	/** The resource the grant was authorized for; an upstream that needs it at authorization needs it here too. */
	readonly resource?: string;
	/** Aborts the upstream request (D12). */
	readonly signal?: AbortSignal;
}

/**
 * What a delegated refresh answers. Every field is optional on purpose: an
 * answer the adapter's library refused to parse may still carry the rotated
 * refresh token, and that one must never be lost (#593, D5) — so `{ refreshToken }`
 * alone is a valid answer, and core treats an answer without a usable access
 * token as `malformed_token_response`.
 *
 * One type, read by both ends: the capability answers with it and
 * `../federation-grants/retrieve.mts` consumes it. Until #626 P1 the two ends
 * were two identical declarations, and this one described the other.
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
	 * The adapter's own `now + expiresIn`. Paired with `expiresIn` it anchors
	 * when the token was obtained on the ADAPTER's reading of the clock; pairing
	 * `expiresIn` with a later reading taken downstream would extend the expiry.
	 * `null` when the upstream named no lifetime.
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
 * The authorization parameters a delegated adapter owns, and which an
 * operator's `authorizationParams` may therefore not set (#593, D17).
 *
 * An exclusion rather than an allowlist: a closed list of permissible vendor
 * parameters would have to be extended for every IdP that invents one, and
 * the ones that matter are the ones this provider computes — the PKCE
 * challenge, the state, the nonce, the redirect it will check the callback
 * against. Setting any of those from configuration is not customisation, it
 * is taking over the security parameters of the flow.
 *
 * It lives here, next to {@link SupportsDelegatedAuthorization}, because two
 * readers need exactly the same set and neither owns it: the adapter that
 * builds the URL refuses these at the point of use, and the federation-grant
 * routes refuse them at boot, where an operator finds out before a user is
 * standing in front of a consent page.
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
 * What the connect callback asks of an adapter (#593, D7, D17): exchange the
 * code the upstream sent back for the grant's first tokens, and say whose they
 * are.
 *
 * Not the login flow's `exchangeCode`. That one answers a login profile — it
 * may call UserInfo, map claims, and fill a lifetime the upstream never sent —
 * and it has no place for three things an acquisition needs: the RFC 8707
 * `resource` at the token endpoint, the lifetime the upstream SENT rather than
 * what a library coerced it to, and a per-call signal for the callback's time
 * budget.
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
	 * The id_token claims to carry beside the subject (#611) — what a Store
	 * matches a person on across registrations where `sub` is pairwise, such
	 * as Entra's `tid` and `oid`. A local allowlist: nothing about it is sent
	 * upstream. Omitted means none. Names are checked by
	 * {@link identityClaimsProblem}.
	 */
	readonly identityClaims?: readonly string[];
}

/**
 * The id_token claims {@link DelegatedCodeExchangeRequest.identityClaims} may
 * not name (#611): the protocol's own bindings and the token's and session's
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
 * is (#611). Case-sensitive names of printable ASCII without spaces, none
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
 * The claims asked for, out of a VERIFIED id_token's (#611): own properties
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
 * The capability behind federation grants (#593, D17): an adapter that can
 * send a user to authorize a delegation, exchange the code that comes back for
 * the grant's first tokens, and refresh them without a session. Detected by
 * ALL THREE methods being present; an adapter with some and not the others
 * does not have it — slice 6 added the exchange, and an adapter written
 * against the earlier pair is refused at boot by name rather than failing at a
 * callback with a user waiting.
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
