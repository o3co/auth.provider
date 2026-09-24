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
	codeChallenge,
	defineModule,
	type EndSessionRequest,
	type EndSessionResult,
	type FederationProfile,
	type FederationProvider,
	type MappedClaims,
	parseScopeTokens,
	type SupportsClaimMapping,
	type SupportsLogout,
} from "@o3co/auth-provider-core";
import { createFederationRedirectPolicy } from "@o3co/auth-provider-session";
import * as oidc from "openid-client";

// ComponentMap slot declaration-merge: exposes githubFederationConfig as a typed
// DI slot. Consumers supply this via a small bootstrap module that reads from
// app config (per A5 §10.2 const-Module pattern).
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly githubFederationConfig?: GithubProviderConfig;
	}
}

const GITHUB_ISSUER = "https://github.com";
const SCOPES = ["read:user", "user:email"] as const;
const GITHUB_USER_URL = "https://api.github.com/user";
const GITHUB_EMAILS_URL = "https://api.github.com/user/emails";
/**
 * GitHub's recommended REST request headers: its JSON media type, and the API
 * version the `sub` rule reads `id` against (an int64 integer), pinned rather
 * than left to whatever version GitHub serves by default. GitHub supports a
 * version for at least 24 months after its successor ships (2022-11-28's
 * shipped 2026-03-10): revisit this pin before 2028-03, or every login fails
 * once GitHub retires it.
 */
const GITHUB_API_HEADERS = {
	accept: "application/vnd.github+json",
	"x-github-api-version": "2022-11-28",
} as const;

export interface GithubProviderConfig {
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
	/** Override GitHub's end-session endpoint. When omitted, the provider redirects directly
	 *  to postLogoutRedirectUri. */
	endSessionEndpoint?: string;
	/**
	 * The fetch every request to GitHub goes through — the token exchange,
	 * `/user` and `/user/emails`. A proxy, or a test seam. Default: the global
	 * `fetch`.
	 */
	fetch?: typeof fetch;
}

export type GithubProvider = FederationProvider & SupportsLogout & SupportsClaimMapping;

/**
 * GitHub's granted scope, as the space-delimited list the rest of the system
 * speaks (RFC 6749 §3.3).
 *
 * GitHub answers with a comma-delimited string. Every consumer here splits on
 * spaces, so the translation belongs at the boundary where the difference is
 * known — this adapter — rather than in a consumer that would then have to
 * know which upstream it is reading.
 */
const githubScope = (value: unknown): string | undefined => {
	// `undefined` means GitHub named no scope at all, which the session route
	// reads as "as requested" (RFC 6749 §3.3). An answer that is present and
	// names nothing usable must NOT flatten into that: the upstream spoke, and
	// reading its silence where there was none would record every requested
	// scope as consent. Present-but-empty travels as the empty string.
	if (value === undefined) return undefined;
	if (typeof value !== "string") return "";
	// Commas to spaces first, then core's grammar. GitHub's delimiter is the
	// only thing this adapter knows that core does not, so it is the only thing
	// this function does.
	return parseScopeTokens(value.replaceAll(",", " ")).join(" ");
};

const isJsonObject = (value: unknown): value is Record<string, unknown> =>
	typeof value === "object" && value !== null && !Array.isArray(value);

/**
 * GET a GitHub REST resource with the user's access token and answer its JSON
 * body. Throws when GitHub answers a non-2xx status — after releasing the body
 * it will not read — or a body that is not JSON.
 *
 * These are GitHub's REST API, not OpenID Connect endpoints, so the library is
 * asked only to carry the request; reading the answer is this adapter's job.
 */
const getGithubJson = async (
	oidcConfig: oidc.Configuration,
	accessToken: string,
	url: string,
): Promise<unknown> => {
	const res = await oidc.fetchProtectedResource(
		oidcConfig,
		accessToken,
		new URL(url),
		"GET",
		undefined,
		new Headers(GITHUB_API_HEADERS),
	);
	if (!res.ok) {
		// Released, not left for the connection to wait on. A failure to cancel
		// must not replace the error that says what GitHub answered.
		await res.body?.cancel().catch(() => undefined);
		throw new Error(`GitHub federation "github": GET ${url} answered HTTP ${res.status}`);
	}
	try {
		return await res.json();
	} catch {
		throw new Error(`GitHub federation "github": GET ${url} answered a body that is not JSON`);
	}
};

/** A positive integer in decimal digits, no sign and no leading zero: what `String(n)` gives for one. */
const DECIMAL_ID = /^[1-9][0-9]*$/;

/**
 * The profile `sub` for GitHub's user object: a non-empty string `sub` when it
 * carries one, otherwise its `id` — a positive safe integer as a decimal
 * string, or a string of decimal digits (no sign, no leading zero) as it is.
 * `undefined` when neither is usable.
 *
 * GitHub types `id` as an int64 integer. The identity handed to the Store is
 * `github:<id>`, so an id outside the safe-integer range after
 * `Response.json()` (`JSON.parse`) is not one — a parsed number there no
 * longer names one id: at 2^53 or above, two ids parse as the same number, and
 * `1e400` parses as `Infinity`. Taken as they came,
 * two GitHub users would sign in as one account. The
 * string form is held to the digits `String(n)` would give, so one user
 * cannot arrive under two spellings.
 */
const githubSub = (user: Record<string, unknown>): string | undefined => {
	if (typeof user.sub === "string" && user.sub !== "") return user.sub;
	const id = user.id;
	if (typeof id === "number") return Number.isSafeInteger(id) && id > 0 ? String(id) : undefined;
	if (typeof id === "string") return DECIMAL_ID.test(id) ? id : undefined;
	return undefined;
};

export function createGithubProvider(config: GithubProviderConfig): GithubProvider {
	if (!config.clientId || !config.clientSecret || !config.callbackURL) {
		throw new Error(`GitHub federation "github" requires clientId, clientSecret, and callbackURL`);
	}

	// GitHub does not expose an OIDC discovery document, so we construct ServerMetadata manually.
	// Local variable type (oidc.ServerMetadata) does not survive to the .d.mts.
	// No `userinfo_endpoint`: GitHub has none. `/user` is read as a protected
	// resource in exchangeCode.
	const serverMetadata: oidc.ServerMetadata = {
		issuer: GITHUB_ISSUER,
		authorization_endpoint: "https://github.com/login/oauth/authorize",
		token_endpoint: "https://github.com/login/oauth/access_token",
	};

	const oidcConfig = new oidc.Configuration(serverMetadata, config.clientId, config.clientSecret);
	// `fetchProtectedResource` goes through the same configuration, so /user
	// and /user/emails take this fetch as the token request does.
	if (config.fetch) oidcConfig[oidc.customFetch] = config.fetch as unknown as oidc.CustomFetch;

	return {
		name: "github",
		scope: SCOPES,

		buildAuthorizationUrl(params: {
			readonly redirectUri: string;
			readonly state: string;
			readonly codeVerifier: string;
		}): URL {
			return oidc.buildAuthorizationUrl(oidcConfig, {
				redirect_uri: params.redirectUri,
				scope: SCOPES.join(" "),
				state: params.state,
				code_challenge: codeChallenge(params.codeVerifier),
				code_challenge_method: "S256",
			});
		},

		async exchangeCode(params: {
			readonly code: string;
			readonly codeVerifier: string;
			readonly redirectUri: string;
		}): Promise<FederationProfile> {
			// Synthesize the callback URL from redirectUri + code.
			//
			// #597: unlike the OIDC, Google and Apple providers this one does NOT
			// forward the callback's RFC 9207 `iss` to the library — yet. GitHub's
			// published metadata (/.well-known/oauth-authorization-server/login/oauth)
			// names its issuer "https://github.com/login/oauth" and advertises the
			// parameter. GITHUB_ISSUER, "https://github.com", is this provider's
			// label for the profile, and it is also what the library is configured
			// with. Forwarding `iss` today would compare the two and refuse every
			// GitHub login. Doing it properly — the library's issuer set to
			// GitHub's own, the profile label kept — is #598.
			const callbackUrl = new URL(params.redirectUri);
			callbackUrl.searchParams.set("code", params.code);

			const tokens = await oidc.authorizationCodeGrant(oidcConfig, callbackUrl, {
				pkceCodeVerifier: params.codeVerifier,
				expectedState: oidc.skipStateCheck,
			});

			// The user is GitHub's REST `GET /user`, which is not an OpenID Connect
			// UserInfo endpoint: it answers a numeric `id` and no `sub`. It is
			// fetched as a protected resource and read here, not through
			// `oidc.fetchUserInfo`: the library requires a string `sub` in a
			// UserInfo body, and checks it before it looks at `skipSubjectCheck`,
			// so it refused every real GitHub user.
			//
			// PB-5 N/A for GitHub: GitHub OAuth Apps issue no id_token, so there is
			// no id_token `sub` to bind the user to (OIDC §5.3.2 applies only when
			// an id_token is in scope). Do NOT mirror the Google PB-5 fix here.
			const body = await getGithubJson(oidcConfig, tokens.access_token, GITHUB_USER_URL);
			// A body that is not a JSON object is treated as a user with no id or
			// sub, and so is a user whose id githubSub refuses: either fails the
			// exchange below.
			const user: Record<string, unknown> = isJsonObject(body) ? body : {};
			const sub = githubSub(user);
			if (sub === undefined) {
				throw new Error(
					`GitHub federation "github" received a /user without id/sub (an id must be a positive safe integer, or a string of decimal digits with no sign or leading zero)`,
				);
			}

			// Fetch primary+verified email from /user/emails.
			// GitHub's /user endpoint often omits email for users who keep it private.
			// Fallback order:
			//   1. primary + verified email
			//   2. first verified email (when primary is unverified)
			//   3. undefined (no verified email at all)
			let email: string | undefined;
			let emailVerified: boolean | undefined;
			try {
				const rows = await getGithubJson(oidcConfig, tokens.access_token, GITHUB_EMAILS_URL);
				if (Array.isArray(rows)) {
					// A row that is not an object is skipped: it must not take the
					// valid addresses beside it down with it.
					const verified = rows
						.filter(isJsonObject)
						.filter((r) => r.verified === true && typeof r.email === "string");
					const primary = verified.find((r) => r.primary === true);
					const chosen = primary ?? verified[0];
					if (chosen && typeof chosen.email === "string") {
						email = chosen.email;
						emailVerified = true;
					}
				}
			} catch {
				// Transient /user/emails failure treated as "no email available" — never kills login.
			}

			const expiresIn = typeof tokens.expires_in === "number" ? tokens.expires_in : undefined;

			return {
				issuer: GITHUB_ISSUER,
				sub,
				email,
				emailVerified,
				name: typeof user.name === "string" ? user.name : undefined,
				// GitHub's /user returns `avatar_url` (not the OIDC `picture` field).
				picture: typeof user.avatar_url === "string" ? user.avatar_url : undefined,
				accessToken: tokens.access_token,
				// RFC 6749 §5.1: the upstream states its scope whenever it differs
				// from the request, so what it says here is what it granted. GitHub
				// always states it. Dropping it left the route to infer consent from
				// the request instead (#647).
				//
				// Comma-delimited, against §3.3's space-delimited list: GitHub
				// answers `read:user,user:email`. Passed through as it arrives, the
				// whole string reads as ONE scope everywhere downstream, and a
				// client asking whether `user:email` was granted is told no.
				scope: githubScope(tokens.scope),
				// GitHub OAuth Apps do not issue refresh tokens.
				refreshToken: undefined,
				// GitHub OAuth Apps classic tokens have no finite expiry; the new-style
				// user-to-server tokens (`expires_in`-bearing) do. `null` signals "reuse,
				// do not attempt refresh" — see FederationProfile.expiresAt contract.
				expiresAt: expiresIn !== undefined ? new Date(Date.now() + expiresIn * 1000) : null,
			};
		},

		// GitHub has no RP-Initiated Logout endpoint by default.
		// Precedence: (1) configured endSessionEndpoint wins; (2) postLogoutRedirectUri redirect;
		// (3) fallback to https://github.com/logout (preserves pre-Task-3 behaviour, supports GitHub Enterprise).
		async endSession(req: EndSessionRequest): Promise<EndSessionResult> {
			if (config.endSessionEndpoint) {
				let url: URL;
				try {
					url = new URL(config.endSessionEndpoint);
				} catch {
					throw new Error(
						`GitHub federation "github" has an invalid endSessionEndpoint: ${config.endSessionEndpoint}`,
					);
				}
				if (req.idTokenHint) url.searchParams.set("id_token_hint", req.idTokenHint);
				if (req.postLogoutRedirectUri)
					url.searchParams.set("post_logout_redirect_uri", req.postLogoutRedirectUri);
				if (req.state) url.searchParams.set("state", req.state);
				return { url, method: "GET" };
			}
			const base = req.postLogoutRedirectUri ?? `${GITHUB_ISSUER}/logout`;
			let url: URL;
			try {
				url = new URL(base);
			} catch {
				throw new Error(
					`GitHub federation "github" received an invalid postLogoutRedirectUri: ${base}`,
				);
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
			return claims as MappedClaims;
		},
	};
}

/**
 * Const Module for the GitHub federation integration.
 *
 * Contributes both `federations.github` (FederationProvider — upstream OAuth 2
 * protocol) and `federationRedirectPolicies.github` (FederationRedirectPolicy
 * — consumer redirect URL policy).
 *
 * Config supplied via the `githubFederationConfig` ComponentMap slot
 * (per A5 §10.2 const-Module pattern).
 *
 * Per A5 §10.2.
 */
export const githubFederationModule = defineModule({
	name: "federation:github",
	requires: ["githubFederationConfig"] as const,
	contributes: {
		federations: {
			// v0.5.0 is single-tenant: provider.name is fixed at "github".
			// Multi-tenant support deferred to post-publish; consumers needing
			// multiple GitHub apps will get an additive Config shape.
			github: (deps) => createGithubProvider(deps.githubFederationConfig),
		},
		federationRedirectPolicies: {
			github: (deps) => createFederationRedirectPolicy(deps.githubFederationConfig),
		},
	},
});
