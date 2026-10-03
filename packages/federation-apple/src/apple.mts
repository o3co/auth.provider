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
	type FederationClientSecret,
	type FederationProfile,
	type FederationProvider,
	federationTokenSnapshot,
	isLoopbackHostname,
	type MappedClaims,
	type RefreshedTokens,
	resolveClientSecret,
	type SupportsClaimMapping,
	type SupportsLogout,
	type SupportsRefresh,
} from "@o3co/auth-provider-core";
import * as oidc from "openid-client";
import { createAppleClientSecret } from "./client-secret.mjs";

export const APPLE_ISSUER = "https://appleid.apple.com";
const APPLE_JWKS_URI = "https://appleid.apple.com/auth/keys";

/**
 * Apple's documented scope values are `name` and `email` — and requesting
 * either is exactly what makes Apple deliver the callback as a form POST.
 * `openid` is not among the values Apple documents, so it is not sent; the
 * authorization-code flow returns an id_token regardless.
 */
const SCOPES = ["name", "email"] as const;

/** The domain of a Hide My Email relay address. */
export const APPLE_PRIVATE_RELAY_DOMAIN = "privaterelay.appleid.com";

/**
 * Whether an address is an Apple Hide My Email relay.
 *
 * Exact-domain match, case-insensitive. A suffix test would accept
 * `privaterelay.appleid.com.attacker.example`, which is a domain an attacker
 * can register.
 */
export function isPrivateRelayEmail(email: string): boolean {
	const at = email.lastIndexOf("@");
	if (at < 0) return false;
	return email.slice(at + 1).toLowerCase() === APPLE_PRIVATE_RELAY_DOMAIN;
}

/**
 * Read a claim Apple sends as either a boolean or the *string* `"true"` /
 * `"false"` (`email_verified`, `is_private_email`). `Boolean("false")` is
 * `true`, so a coercion would report an unverified address as verified.
 * Anything that is neither shape reads as absent, because absence is not
 * `false`.
 */
const normalizeBooleanClaim = (value: unknown): boolean | undefined => {
	if (typeof value === "boolean") return value;
	if (value === "true") return true;
	if (value === "false") return false;
	return undefined;
};

/**
 * Read the display name out of the `user` field Apple POSTs on the *first*
 * authorization only.
 *
 * A JSON string relayed through the user agent: parsed defensively, a
 * malformed or oddly shaped body yields no name, never a failed login. It is
 * unsigned — the `state` check binds it to this session and nothing more —
 * so it is self-asserted and reaches the claims envelope only under the
 * ordinary promotion rules. `name` is promotable, so each part is bounded by
 * {@link APPLE_NAME_PART_MAX_LENGTH} to keep attacker text out of the claims
 * envelope and session store; a part over the cap is dropped whole, because
 * a truncated one is still the attacker's text.
 */
const parseUserName = (raw: string | undefined): string | undefined => {
	if (typeof raw !== "string" || raw.length === 0) return undefined;
	let parsed: unknown;
	try {
		parsed = JSON.parse(raw);
	} catch {
		return undefined;
	}
	if (parsed == null || typeof parsed !== "object") return undefined;
	const name = (parsed as { name?: unknown }).name;
	if (name == null || typeof name !== "object") return undefined;
	const { firstName, lastName } = name as { firstName?: unknown; lastName?: unknown };
	const parts = [firstName, lastName].filter(
		(part): part is string =>
			typeof part === "string" && part.length > 0 && part.length <= APPLE_NAME_PART_MAX_LENGTH,
	);
	return parts.length > 0 ? parts.join(" ") : undefined;
};

/**
 * The longest `firstName` / `lastName` the unsigned `user` body may
 * contribute to the display name, in UTF-16 code units. Generous
 * for any real name; a part beyond it is dropped, not truncated.
 */
export const APPLE_NAME_PART_MAX_LENGTH = 128;

export interface AppleProviderConfig {
	/**
	 * The **Services ID** (e.g. `com.example.app.service`), not the App ID.
	 * Apple treats a web OAuth client as a Services ID configured under an App
	 * ID; the bundle identifier itself is never the `client_id` here.
	 */
	clientId: string;
	/**
	 * Return URL registered against the Services ID.
	 *
	 * Two separate rules, both checked at construction rather than discovered
	 * as an opaque `invalid_request` at the authorization endpoint: the scheme
	 * must be `https`, **and** the host must not be loopback — Apple rejects
	 * `localhost`, `127.0.0.0/8` and `[::1]` even over `https`, so local
	 * development needs a tunnel or a dev hostname holding a certificate.
	 */
	callbackURL: string;
	/**
	 * The client secret, either already-computed or a resolver. Supply this
	 * **or** `teamId` + `keyId` + `privateKey`, never both.
	 *
	 * Apple's secret is an ES256 JWT capped at six months, so the practical
	 * form is a resolver — `createAppleClientSecret(...)`, which this module
	 * builds for you when you hand it the key material instead.
	 */
	clientSecret?: FederationClientSecret;
	/** Apple Developer Team ID. With `keyId` + `privateKey`, builds the signer. */
	teamId?: string;
	/** Key ID of the downloaded `.p8`. */
	keyId?: string;
	/** The `.p8` private key, PKCS#8 PEM. */
	privateKey?: string;
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
	/**
	 * Upstream logout endpoint. Apple publishes no `end_session_endpoint`, so
	 * absent this the provider can only redirect to `postLogoutRedirectUri`.
	 */
	endSessionEndpoint?: string;
	/** Override Apple's JWKS URI. Default: `https://appleid.apple.com/auth/keys`.
	 *  Test injection only — production deployments rely on the default. */
	jwksUri?: string;
	/**
	 * The fetch every request to Apple goes through — JWKS and token. A proxy,
	 * or a test seam. Default: the global `fetch`.
	 */
	fetch?: typeof fetch;
}

export type AppleProvider = FederationProvider &
	SupportsRefresh &
	SupportsLogout &
	SupportsClaimMapping;

/**
 * Resolve the one client-secret source this config declares.
 *
 * Exactly one of the two forms, checked at construction: a deployment that
 * supplies both has two answers to "which key signs this?", and a deployment
 * that supplies neither has none. Either is a boot-time misconfiguration and
 * belongs at boot, not at the first login attempt.
 */
function resolveSecretSource(name: string, config: AppleProviderConfig): FederationClientSecret {
	const hasKeyMaterial = config.teamId != null || config.keyId != null || config.privateKey != null;
	const hasClientSecret = config.clientSecret != null;

	if (hasClientSecret && hasKeyMaterial) {
		throw new Error(
			`Apple federation "${name}" takes either a clientSecret or teamId/keyId/privateKey, not both`,
		);
	}
	if (hasClientSecret) {
		return config.clientSecret as FederationClientSecret;
	}
	if (!hasKeyMaterial) {
		throw new Error(
			`Apple federation "${name}" requires a clientSecret, or teamId + keyId + privateKey to sign one`,
		);
	}
	// `createAppleClientSecret` names whichever piece is missing. `privateKey`
	// is read through to the caller's config at every resolve rather than
	// copied now, so a rotation the caller exposes as a getter or a re-read
	// file reaches the signer through this path too.
	return createAppleClientSecret({
		teamId: config.teamId as string,
		clientId: config.clientId,
		keyId: config.keyId as string,
		get privateKey() {
			return config.privateKey as string;
		},
	});
}

/**
 * The Sign in with Apple provider for the federation `apple`, built from code:
 * the provider `appleFederationTypeModule()` builds under each entry's name,
 * with what an entry cannot carry — a client-secret resolver, a `privateKey`
 * read at every signing, a `jwksUri` override.
 */
export function createAppleProvider(config: AppleProviderConfig): AppleProvider {
	return buildAppleProvider("apple", config);
}

/**
 * The provider for the federation `name`: the `:name` route segment, the name
 * its tokens are stored under, and the prefix of the identity handed to the
 * Store (`<name>:<sub>`). Every refusal names it.
 */
export function buildAppleProvider(name: string, config: AppleProviderConfig): AppleProvider {
	if (!config.clientId) {
		throw new Error(`Apple federation "${name}" requires clientId (the Services ID)`);
	}
	if (!config.callbackURL) {
		throw new Error(`Apple federation "${name}" requires callbackURL`);
	}

	// Apple's return URL is checked here, at boot, because every way it can be
	// wrong produces the same opaque `invalid_request` from the authorization
	// endpoint at the worst possible moment — the first login attempt. The
	// value the flow actually sends is held to this one below.
	let callbackUrl: URL;
	try {
		callbackUrl = new URL(config.callbackURL);
	} catch {
		throw new Error(
			`Apple federation "${name}" received a callbackURL that is not a URL: ${config.callbackURL}`,
		);
	}
	if (callbackUrl.protocol !== "https:") {
		throw new Error(
			`Apple federation "${name}" requires an https callbackURL — Apple refuses a plain-http return URL (got ${config.callbackURL})`,
		);
	}
	// `https` is necessary and not sufficient: Apple refuses a loopback return
	// URL whatever its scheme, so `https://localhost/cb` clears the check above
	// and still fails upstream. `isLoopbackHostname` is the repo's one
	// definition (`core/src/net/loopback.mts`), covering `localhost`, the whole
	// 127.0.0.0/8 block and bracketed `[::1]` as `URL.hostname` reports it.
	if (isLoopbackHostname(callbackUrl.hostname)) {
		throw new Error(
			`Apple federation "${name}" refuses a loopback callbackURL (${config.callbackURL}) — Apple rejects localhost, 127.0.0.0/8 and [::1] return URLs even over https, so local development needs a tunnel or a dev hostname holding a certificate`,
		);
	}

	// The guard above validated `config.callbackURL`, but the `redirect_uri`
	// the flow sends is what the session module derived from
	// `core.federations.<name>.callbackURL`. In every shipped composition
	// they are one value; a composition where they drift fails loudly at the
	// first request instead of sending Apple a return URL nobody validated.
	const requireConfiguredCallback = (redirectUri: string): string => {
		if (redirectUri !== config.callbackURL) {
			throw new Error(
				`Apple federation "${name}" was handed a redirect URI (${redirectUri}) that is not the configured callbackURL (${config.callbackURL}) — the route derives it from core.federations.<name>.callbackURL, and the two must agree`,
			);
		}
		return redirectUri;
	};

	const clientSecret = resolveSecretSource(name, config);

	// ServerMetadata constructed locally — no discovery call. Apple's endpoints
	// are stable, and Apple publishes no `userinfo_endpoint` and no
	// `end_session_endpoint`. The RS256 pin (what Apple signs with) refuses
	// `none` / `HS256` confusion; it and `jwks_uri` take effect only through
	// `verifying` below.
	const serverMetadata: oidc.ServerMetadata = {
		issuer: APPLE_ISSUER,
		authorization_endpoint: "https://appleid.apple.com/auth/authorize",
		token_endpoint: "https://appleid.apple.com/auth/token",
		jwks_uri: config.jwksUri ?? APPLE_JWKS_URI,
		id_token_signing_alg_values_supported: ["RS256"],
	};

	/**
	 * Every configuration this provider builds verifies the id_token's signature
	 * against `jwks_uri`: on the code flow openid-client 6 skips it unless told
	 * to, treating the token endpoint's TLS as proof enough. Apple publishes no
	 * userinfo endpoint, so the id_token is the only source of identity and its
	 * signature the only check between that TLS and the account. Applied per
	 * configuration, because the token one is rebuilt on every call.
	 */
	const verifying = (configuration: oidc.Configuration): oidc.Configuration => {
		if (config.fetch) {
			configuration[oidc.customFetch] = config.fetch as unknown as oidc.CustomFetch;
		}
		oidc.enableNonRepudiationChecks(configuration);
		return configuration;
	};

	// Building an authorization URL needs no client authentication, so this
	// configuration carries no secret and never triggers the ES256 signature.
	const authorizationConfig = verifying(new oidc.Configuration(serverMetadata, config.clientId));

	/**
	 * A configuration for one token-endpoint call, with the secret resolved now.
	 * Rebuilt per call because the secret rotates: one frozen into a
	 * Configuration stops authenticating six months after setup. Apple requires
	 * `client_secret_post`, stated rather than inherited from the library default.
	 */
	const tokenConfiguration = async (): Promise<oidc.Configuration> => {
		const secret = await resolveClientSecret(clientSecret);
		return verifying(
			new oidc.Configuration(
				serverMetadata,
				config.clientId,
				secret,
				oidc.ClientSecretPost(secret),
			),
		);
	};

	const requireNonce = (nonce: string | undefined): string => {
		if (typeof nonce !== "string" || nonce.length === 0) {
			throw new Error(
				`Apple federation "${name}" requires a non-empty nonce — OIDC §3.1.3.7 nonce binding is mandatory.`,
			);
		}
		return nonce;
	};

	return {
		name,
		scope: SCOPES,
		// Apple POSTs the callback whenever `scope` includes `name` or `email`,
		// which SCOPES always does. The route layer reads this to send
		// `response_mode=form_post` upstream, to accept the POST callback, and to
		// mark this federation's state cookie SameSite=None; Secure.
		responseMode: "form_post",

		buildAuthorizationUrl(params: {
			readonly redirectUri: string;
			readonly state: string;
			readonly codeVerifier: string;
			readonly nonce?: string;
		}): URL {
			const nonce = requireNonce(params.nonce);
			return oidc.buildAuthorizationUrl(authorizationConfig, {
				redirect_uri: requireConfiguredCallback(params.redirectUri),
				scope: SCOPES.join(" "),
				state: params.state,
				code_challenge: codeChallenge(params.codeVerifier),
				code_challenge_method: "S256",
				nonce,
			});
		},

		async exchangeCode(params: {
			readonly code: string;
			readonly codeVerifier: string;
			readonly redirectUri: string;
			readonly nonce?: string;
			readonly callbackParams?: Readonly<Record<string, string>>;
		}): Promise<FederationProfile> {
			const nonce = requireNonce(params.nonce);

			// openid-client's authorizationCodeGrant expects the full callback URL.
			// Apple POSTs the parameters instead, so the URL is synthesized from the
			// registered return URL plus the code, as the Google adapter does for a
			// query-mode callback. An RFC 9207 `iss` in the posted body goes with it,
			// so one Apple does send is compared with APPLE_ISSUER.
			const callbackUrl = callbackUrlForExchange({
				redirectUri: requireConfiguredCallback(params.redirectUri),
				code: params.code,
				callbackParams: params.callbackParams,
			});

			// `expectedNonce` activates openid-client's nonce check (OIDC §3.1.3.7)
			// and also asserts an id_token is present in the response.
			const tokens = await oidc.authorizationCodeGrant(await tokenConfiguration(), callbackUrl, {
				pkceCodeVerifier: params.codeVerifier,
				expectedState: oidc.skipStateCheck,
				expectedNonce: nonce,
			});
			// The token's lifetime is dated from when the library handed the answer
			// over, after it verified the id_token.
			const obtainedAt = Date.now();

			// Apple publishes no userinfo endpoint: the verified id_token is the
			// only source of identity, so there is no UserInfo/id_token binding to
			// make and nothing to fetch.
			const claims = tokens.claims();
			const sub = claims?.sub;
			if (typeof sub !== "string" || sub.length === 0) {
				throw new Error(`Apple federation "${name}" id_token is missing the sub claim`);
			}

			const email = typeof claims?.email === "string" ? claims.email : undefined;
			// Apple's own marker wins; the relay domain answers only when Apple
			// said nothing, so a real address is never mislabelled by inference.
			const isPrivateEmail =
				normalizeBooleanClaim(claims?.is_private_email) ??
				(email !== undefined ? isPrivateRelayEmail(email) : undefined);

			const profile: FederationProfile = {
				issuer: APPLE_ISSUER,
				sub,
				email,
				emailVerified: normalizeBooleanClaim(claims?.email_verified),
				// The name exists in the first authorization's POST body and nowhere
				// else — never in the id_token, and never again on a later login.
				name: parseUserName(params.callbackParams?.user),
				// The tokens as Apple stated them: the lifetime as sent or none,
				// the scope as sent (what it granted, RFC 6749 §5.1), and the
				// token type — core's one reading for every adapter.
				...federationTokenSnapshot(tokens, obtainedAt),
			};

			if (isPrivateEmail !== undefined) {
				(profile as Record<string, unknown>).isPrivateEmail = isPrivateEmail;
			}

			return profile;
		},

		async refreshToken(refreshTokenValue: string): Promise<RefreshedTokens> {
			// sub / issuer intentionally absent — callers reuse stored identity.
			return federationTokenSnapshot(
				await oidc.refreshTokenGrant(await tokenConfiguration(), refreshTokenValue),
			);
		},

		async endSession(req: EndSessionRequest): Promise<EndSessionResult> {
			// Apple publishes no OIDC end_session_endpoint and, unlike Google, no
			// logout URL to send a browser to. So an operator-supplied endpoint,
			// else the deployment's own post-logout page, else a loud failure
			// rather than a redirect somewhere invented. The postLogoutRedirectUri
			// handed here is already matched against the client's registered
			// postLogoutRedirectUris, or absent (core's `EndSessionRequest`
			// contract; `oauth`'s logout routes check it first).
			if (config.endSessionEndpoint) {
				let url: URL;
				try {
					url = new URL(config.endSessionEndpoint);
				} catch {
					throw new Error(
						`Apple federation "${name}" has an invalid endSessionEndpoint: ${config.endSessionEndpoint}`,
					);
				}
				if (req.idTokenHint) url.searchParams.set("id_token_hint", req.idTokenHint);
				if (req.postLogoutRedirectUri)
					url.searchParams.set("post_logout_redirect_uri", req.postLogoutRedirectUri);
				if (req.state) url.searchParams.set("state", req.state);
				return { url, method: "GET" };
			}
			if (!req.postLogoutRedirectUri) {
				throw new Error(
					`Apple federation "${name}" cannot start an upstream logout: Apple publishes no end_session_endpoint, so either configure endSessionEndpoint or pass postLogoutRedirectUri`,
				);
			}
			let url: URL;
			try {
				url = new URL(req.postLogoutRedirectUri);
			} catch {
				// Named, not quoted: the message reaches a log line as the error's
				// `detail`, and the value is not this adapter's text.
				throw new Error(
					`Apple federation "${name}" received an invalid postLogoutRedirectUri: not a URL`,
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
			// Apple extension: whether the address is a Hide My Email relay.
			// Recorded under `claims.federated.<name>` (never promoted) so a
			// deployment that must reach a real inbox can decide what to do.
			if (typeof profile.isPrivateEmail === "boolean")
				claims.isPrivateEmail = profile.isPrivateEmail;
			return claims as MappedClaims;
		},
	};
}
