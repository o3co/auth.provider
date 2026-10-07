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

import {
	callbackUrlForExchange,
	codeChallenge,
	type EndSessionRequest,
	type EndSessionResult,
	type FederationProfile,
	type FederationProvider,
	federationTokenSnapshot,
	type MappedClaims,
	type RefreshedTokens,
	readUpstreamAuthTime,
	type SupportsClaimMapping,
	type SupportsLogout,
	type SupportsRefresh,
} from "@o3co/auth-provider-core";
import * as oidc from "openid-client";

const GOOGLE_ISSUER = "https://accounts.google.com";
const SCOPES = ["openid", "profile", "email"] as const;
const GOOGLE_JWKS_URI = "https://www.googleapis.com/oauth2/v3/certs";

export interface GoogleProviderConfig {
	clientId: string;
	clientSecret: string;
	callbackURL: string;
	/**
	 * Exact URLs a consumer-supplied `redirect_to` may name. Absent or empty
	 * means no `redirect_to` is accepted at all — see `createFederationRedirectPolicy`.
	 */
	redirectAllowlist?: readonly string[];
	/** Cookie / session domain; every non-loopback `redirectAllowlist` entry must be inside it. Optional. */
	sessionDomain?: string;
	/** URL of the auth-callback page (used to build the post-login redirect). Optional. */
	authCallbackUrl?: string;
	/** Fallback URL for the client app (used when no redirectTo is present). Optional. */
	clientUrl?: string;
	/** Override Google's end-session endpoint. When omitted, the provider redirects directly
	 *  to postLogoutRedirectUri (or accounts.google.com/Logout as fallback). */
	endSessionEndpoint?: string;
	/** Override Google's JWKS URI. Default: `https://www.googleapis.com/oauth2/v3/certs`.
	 *  Test injection only — production deployments rely on the default. */
	jwksUri?: string;
	/**
	 * Whether a callback without the RFC 9207 `iss` parameter is refused.
	 * Default `true`: Google's discovery document advertises
	 * `authorization_response_iss_parameter_supported`, and its reference says
	 * the parameter "is always returned". This metadata is hand-built, so should
	 * Google stop sending it, `false` lets deployments log in without waiting
	 * for a release. It permits absence only: an `iss` that is sent and is not
	 * Google's is refused either way.
	 */
	requireAuthorizationResponseIss?: boolean;
	/**
	 * Whether sign-in asks Google for a refresh token. Default `"offline"`
	 * when omitted; any other value, `null` included, is refused at
	 * construction.
	 *
	 * Google issues a refresh token only on its consent screen, which it shows
	 * unprompted only the first time, and upstream tokens are kept per session.
	 * So `"offline"` sends `access_type=offline` **and** `prompt=consent`: every
	 * sign-in shows the consent screen and every session gets a refresh token
	 * for `POST /oauth/federation/google/token`. `"online"` sends neither: no
	 * consent screen after the first sign-in and no refresh token, for a
	 * deployment that never refreshes Google's access token.
	 */
	accessType?: "offline" | "online";
	/**
	 * The fetch every request to Google goes through — JWKS, token, userinfo.
	 * A proxy, or a test seam. Default: the global `fetch`.
	 */
	fetch?: typeof fetch;
}

export type GoogleProvider = FederationProvider &
	SupportsRefresh &
	SupportsLogout &
	SupportsClaimMapping;

/** The name `createGoogleProvider` gives the provider. */
const DEFAULT_NAME = "google";

export function createGoogleProvider(config: GoogleProviderConfig): GoogleProvider {
	return createNamedGoogleProvider(DEFAULT_NAME, config);
}

/**
 * `createGoogleProvider` under another name: the provider's `name` — the
 * `:name` route segment, the key its tokens are stored under and the prefix
 * of the identity handed to the Store (`<name>:<sub>`) — and the name its
 * errors give. Everything else is the same.
 */
export function createNamedGoogleProvider(
	name: string,
	config: GoogleProviderConfig,
): GoogleProvider {
	const subject = `Google federation ${JSON.stringify(name)}`;
	if (!config.clientId || !config.clientSecret || !config.callbackURL) {
		throw new Error(`${subject} requires clientId, clientSecret, and callbackURL`);
	}
	// The library reads this as a truthy flag, and an environment override
	// arrives as the string "false" — which is truthy. A caller that forwards it
	// uncoerced would leave the requirement on during the very incident the
	// switch exists for, so anything that is not a boolean is refused here.
	if (
		config.requireAuthorizationResponseIss !== undefined &&
		typeof config.requireAuthorizationResponseIss !== "boolean"
	) {
		throw new Error(
			`${subject}: requireAuthorizationResponseIss must be a boolean — coerce an environment string before passing it`,
		);
	}

	// Only an omitted field means the default: an explicit `null` from a JS
	// caller is a value, and refused like any other that is not one of the two.
	const accessType = config.accessType === undefined ? "offline" : config.accessType;
	if (accessType !== "offline" && accessType !== "online") {
		// A string is quoted (escaped, so it cannot break the line); a number,
		// a boolean or null is printed as itself; anything else is named by
		// its type — JSON.stringify throws on a bigint and prints nothing for a
		// symbol or a function.
		const got =
			typeof accessType === "string"
				? JSON.stringify(accessType)
				: accessType === null || typeof accessType === "number" || typeof accessType === "boolean"
					? String(accessType)
					: typeof accessType;
		throw new Error(`${subject}: accessType must be "offline" or "online", got ${got}`);
	}
	// Offline access asks for the consent screen on every sign-in (see
	// `accessType`): tokens are kept per session, and an earlier session's
	// refresh token is not reachable from a new one — keeping one per
	// `<name>:<sub>` would be a store that outlives sessions.
	const offlineAccess: Readonly<Record<string, string>> =
		accessType === "offline" ? { access_type: "offline", prompt: "consent" } : {};

	// ServerMetadata constructed locally — no discovery call. Google's endpoints are stable.
	// Local variable type (oidc.ServerMetadata) does not survive to the .d.mts.
	//
	// The RS256 pin refuses `none` / `HS256` confusion should the published
	// JWKS be coerced. It and `jwks_uri` take effect only through
	// `enableNonRepudiationChecks` below.
	const serverMetadata: oidc.ServerMetadata = {
		issuer: GOOGLE_ISSUER,
		authorization_endpoint: "https://accounts.google.com/o/oauth2/v2/auth",
		token_endpoint: "https://oauth2.googleapis.com/token",
		userinfo_endpoint: "https://www.googleapis.com/oauth2/v3/userinfo",
		jwks_uri: config.jwksUri ?? GOOGLE_JWKS_URI,
		id_token_signing_alg_values_supported: ["RS256"],
		// Mirrors what Google's own discovery document says. With it the
		// library refuses a callback that carries no `iss`; without it, only one
		// that carries a wrong `iss`.
		authorization_response_iss_parameter_supported: config.requireAuthorizationResponseIss ?? true,
	};

	const oidcConfig = new oidc.Configuration(serverMetadata, config.clientId, config.clientSecret);
	if (config.fetch) oidcConfig[oidc.customFetch] = config.fetch as unknown as oidc.CustomFetch;
	// Verify the id_token's signature against `jwks_uri` — the key looked up
	// by `kid`, the set cached and refetched when an unknown `kid` appears.
	// openid-client 6 otherwise skips it, accepting a token signed by anyone
	// on the strength of the token endpoint's TLS alone.
	oidc.enableNonRepudiationChecks(oidcConfig);

	return {
		name,
		scope: SCOPES,

		// A freshness ask (`params.ask`) is not forwarded: Google documents
		// `prompt` as `none`, `consent` or `select_account` only, and no `max_age`.
		buildAuthorizationUrl(params: {
			readonly redirectUri: string;
			readonly state: string;
			readonly codeVerifier: string;
			readonly nonce?: string;
		}): URL {
			// Google is OIDC-only, so nonce binding is mandatory (OIDC §3.1.3.7).
			// Fail closed when a caller forgets to thread nonce — silently dropping it would
			// produce an authorization request whose id_token cannot be bound to the session.
			if (typeof params.nonce !== "string" || params.nonce.length === 0) {
				throw new Error(
					`${subject} requires a non-empty nonce — OIDC §3.1.3.7 nonce binding is mandatory.`,
				);
			}
			return oidc.buildAuthorizationUrl(oidcConfig, {
				redirect_uri: params.redirectUri,
				scope: SCOPES.join(" "),
				state: params.state,
				code_challenge: codeChallenge(params.codeVerifier),
				code_challenge_method: "S256",
				...offlineAccess,
				nonce: params.nonce,
			});
		},

		async exchangeCode(params: {
			readonly code: string;
			readonly codeVerifier: string;
			readonly redirectUri: string;
			readonly nonce?: string;
			readonly callbackParams?: Readonly<Record<string, string>>;
		}): Promise<FederationProfile> {
			// Same fail-closed guard as buildAuthorizationUrl: a session with no
			// `nonce` is rejected, so the user re-authenticates with a nonce-bearing
			// one, rather than verification silently degrading.
			if (typeof params.nonce !== "string" || params.nonce.length === 0) {
				throw new Error(
					`${subject} requires a non-empty nonce — OIDC §3.1.3.7 nonce binding is mandatory.`,
				);
			}

			// openid-client's authorizationCodeGrant expects the full callback URL.
			// We synthesize it from redirectUri + code since the route receives them separately.
			// The callback's RFC 9207 `iss`, which Google sends, goes with it, so
			// that the library compares it with GOOGLE_ISSUER.
			const callbackUrl = callbackUrlForExchange({
				redirectUri: params.redirectUri,
				code: params.code,
				callbackParams: params.callbackParams,
			});

			// Passing `expectedNonce` activates openid-client's nonce check (OIDC §3.1.3.7)
			// and *also* asserts an id_token is present in the response.
			const tokens = await oidc.authorizationCodeGrant(oidcConfig, callbackUrl, {
				pkceCodeVerifier: params.codeVerifier,
				expectedState: oidc.skipStateCheck,
				expectedNonce: params.nonce,
			});
			// The token's lifetime is dated from when the library handed the answer
			// over — after it verified the id_token — and not after UserInfo.
			const obtainedAt = Date.now();

			// Bind the UserInfo response sub to the verified id_token sub (OIDC §5.3.2).
			// Google id_tokens always carry a non-empty string sub. If the claim is absent,
			// non-string, or empty we MUST fail closed — falling back to `skipSubjectCheck`
			// would silently downgrade the binding contract for a token we cannot identify.
			const idTokenClaims = tokens.claims();
			const idTokenSub = idTokenClaims?.sub;
			if (typeof idTokenSub !== "string" || idTokenSub.length === 0) {
				throw new Error(
					`${subject} id_token is missing the sub claim required for UserInfo binding (OIDC §5.3.2).`,
				);
			}
			// From the verified id_token alone, never UserInfo.
			const authTime = readUpstreamAuthTime(idTokenClaims?.auth_time);
			if (authTime === "invalid") {
				throw new Error(`${subject} id_token auth_time is not a usable instant (OIDC Core §2).`);
			}
			const userInfo = await oidc.fetchUserInfo(oidcConfig, tokens.access_token, idTokenSub);

			// Extension claims: anything beyond first-class fields lands on the profile
			// via the index signature — no `raw` wrapper needed.
			const profile: FederationProfile = {
				issuer: GOOGLE_ISSUER,
				sub: typeof userInfo.sub === "string" ? userInfo.sub : "",
				email: typeof userInfo.email === "string" ? userInfo.email : undefined,
				emailVerified:
					typeof userInfo.email_verified === "boolean" ? userInfo.email_verified : undefined,
				name: typeof userInfo.name === "string" ? userInfo.name : undefined,
				picture: typeof userInfo.picture === "string" ? userInfo.picture : undefined,
				// The tokens as Google stated them: the lifetime as sent or none,
				// the scope as sent (what it granted, RFC 6749 §5.1), and the
				// token type — core's one reading for every adapter.
				...federationTokenSnapshot(tokens, obtainedAt),
				...(authTime === undefined ? {} : { authTime }),
			};

			// Carry through known extension claims (e.g. Google hd).
			if (typeof userInfo.hd === "string") {
				(profile as Record<string, unknown>).hd = userInfo.hd;
			}

			return profile;
		},

		async refreshToken(refreshTokenValue: string): Promise<RefreshedTokens> {
			// sub / issuer intentionally absent — callers reuse stored identity.
			return federationTokenSnapshot(await oidc.refreshTokenGrant(oidcConfig, refreshTokenValue));
		},

		async endSession(req: EndSessionRequest): Promise<EndSessionResult> {
			// Google does not publish an OIDC end_session_endpoint in its discovery document.
			// Operators MUST pass endSessionEndpoint explicitly for upstream logout.
			// Absent that, redirect directly to postLogoutRedirectUri (or accounts.google.com/Logout).
			// That redirect is safe only because the URI handed here is already
			// matched against the client's registered postLogoutRedirectUris, or
			// none (core's `EndSessionRequest`; `oauth`'s logout routes check it
			// first).
			if (config.endSessionEndpoint) {
				let url: URL;
				try {
					url = new URL(config.endSessionEndpoint);
				} catch {
					throw new Error(
						`${subject} has an invalid endSessionEndpoint: ${config.endSessionEndpoint}`,
					);
				}
				if (req.idTokenHint) url.searchParams.set("id_token_hint", req.idTokenHint);
				if (req.postLogoutRedirectUri)
					url.searchParams.set("post_logout_redirect_uri", req.postLogoutRedirectUri);
				if (req.state) url.searchParams.set("state", req.state);
				return { url, method: "GET" };
			}
			const base = req.postLogoutRedirectUri ?? `${GOOGLE_ISSUER}/Logout`;
			let url: URL;
			try {
				url = new URL(base);
			} catch {
				// Named, not quoted: the message reaches a log line as the error's
				// `detail`, and the value is not this adapter's text. (The fallback
				// above is always a URL, so only a handed value lands here.)
				throw new Error(`${subject} received an invalid postLogoutRedirectUri: not a URL`);
			}
			if (req.state) url.searchParams.set("state", req.state);
			return { url, method: "GET" };
		},

		mapClaims(profile: FederationProfile): MappedClaims {
			const claims: Record<string, unknown> = {};
			if (typeof profile.email === "string") claims.email = profile.email;
			if (typeof profile.emailVerified === "boolean") claims.emailVerified = profile.emailVerified;
			if (typeof profile.name === "string") claims.name = profile.name;
			if (typeof profile.picture === "string") claims.picture = profile.picture;
			// Pass through extension claims (e.g. hd for Google Workspace domain restriction).
			if (typeof profile.hd === "string") claims.hd = profile.hd;
			return claims as MappedClaims;
		},
	};
}
