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

import { isLoopbackHostname } from "@o3co/auth-provider-core";
import {
	codeChallenge,
	type EndSessionRequest,
	type EndSessionResult,
	type FederationClientSecret,
	type FederationProfile,
	type FederationProvider,
	type MappedClaims,
	type RefreshedTokens,
	type SupportsClaimMapping,
	type SupportsLogout,
	type SupportsRefresh,
} from "@o3co/auth-provider-session";
import * as oidc from "openid-client";
import { verifyAtHash } from "./at-hash.mjs";
import { clientAuthFor, type OidcPrivateKey } from "./client-auth.mjs";

/**
 * A generic OpenID Connect federation provider (#524): any OIDC-compliant
 * IdP — Okta, Entra ID, Auth0, Keycloak, a customer's own tenant — from
 * configuration alone, and as many instances as a deployment has issuers.
 *
 * ## What one instance does
 *
 * - **At construction** (boot): resolves the issuer's metadata through
 *   OpenID Connect Discovery. A discovery failure is fatal — there is no
 *   silent fallback to hand-typed endpoints; a deployment that wants those
 *   sets `discovery = false` and writes them down under `endpoints`.
 * - **Authorization request**: `authorization_code` with PKCE S256, `state`
 *   and `nonce`, all three minted by the session routes per transaction.
 * - **Callback**: exchanges the code with `client_secret_basic` or
 *   `private_key_jwt`, then validates the id_token — signature against the
 *   issuer's JWKS (cached, refetched on an unknown `kid`), `iss`, `aud`,
 *   `exp`, `iat`, `nonce`, and `at_hash` when present. UserInfo, when the
 *   issuer publishes it, is bound to the id_token's `sub`.
 * - **Identity**: `sub` is opaque and stable per issuer; the session routes
 *   hand `<name>:<sub>` to the Store, and an identity the Store does not
 *   know is refused — this package provisions nothing.
 */
export const DEFAULT_OIDC_SCOPES = ["openid", "profile", "email"] as const;

export interface OidcEndpointOverrides {
	readonly authorizationEndpoint?: string;
	readonly tokenEndpoint?: string;
	readonly jwksUri?: string;
	readonly userinfoEndpoint?: string;
	readonly endSessionEndpoint?: string;
}

export interface OidcProviderConfig {
	/** Issuer identifier, exactly as the IdP writes it into `iss`. https, or http on loopback. */
	readonly issuer: string;
	readonly clientId: string;
	/** `client_secret_basic`. A resolver is consulted per token request. */
	readonly clientSecret?: FederationClientSecret;
	/** `private_key_jwt`. A PEM PKCS#8 key, or `{ pem, kid?, alg? }`. */
	readonly privateKey?: string | OidcPrivateKey;
	/** Where the IdP sends the browser back; the session routes read it from `federations.<name>`. */
	readonly callbackURL: string;
	/** Default `openid profile email`; `openid` is mandatory. */
	readonly scopes?: readonly string[];
	/** Default true. When false, `endpoints` must name authorization, token and JWKS. */
	readonly discovery?: boolean;
	/** Overrides applied on top of (or instead of) the discovered metadata. */
	readonly endpoints?: OidcEndpointOverrides;
	/** Pin the id_token JWS algorithm; otherwise the issuer's advertised list is trusted. */
	readonly idTokenSignedResponseAlg?: string;
	/** Default: call UserInfo when the issuer publishes an endpoint. */
	readonly userInfo?: boolean;
	/** Clock skew tolerated on JWT time claims. Default 30. */
	readonly clockToleranceSeconds?: number;
	/** The fetch every upstream request goes through — a proxy, or a test seam. */
	readonly fetch?: typeof fetch;
	readonly redirectAllowlist?: readonly string[];
	readonly sessionDomain?: string;
	readonly authCallbackUrl?: string;
	readonly clientUrl?: string;
}

export type OidcProvider = FederationProvider &
	SupportsRefresh &
	SupportsClaimMapping &
	Partial<SupportsLogout>;

const NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;

/** A federation name is the `:name` route segment and the identity prefix; keep it to one plain segment. */
export function checkFederationName(name: unknown): asserts name is string {
	if (typeof name !== "string" || !NAME_PATTERN.test(name)) {
		throw new Error(
			`OIDC federation name must be one URL path segment of letters, digits, ".", "_" or "-", got ${JSON.stringify(name)}`,
		);
	}
}

const message = (err: unknown): string => (err instanceof Error ? err.message : String(err));

const optionalString = (value: unknown): string | undefined =>
	typeof value === "string" && value.length > 0 ? value : undefined;

/** `email_verified` arrives as a boolean or, from some IdPs, as the strings "true" / "false". */
const optionalBoolean = (value: unknown): boolean | undefined => {
	if (typeof value === "boolean") return value;
	if (value === "true") return true;
	if (value === "false") return false;
	return undefined;
};

const stringArray = (value: unknown): readonly string[] | undefined =>
	Array.isArray(value) && value.every((entry) => typeof entry === "string")
		? (value as string[])
		: undefined;

function parseIssuer(label: string, issuer: unknown): URL {
	if (typeof issuer !== "string" || issuer.length === 0) {
		throw new Error(`${label}: issuer is required`);
	}
	let url: URL;
	try {
		url = new URL(issuer);
	} catch {
		throw new Error(`${label}: issuer is not a URL: ${issuer}`);
	}
	if (
		url.protocol !== "https:" &&
		!(url.protocol === "http:" && isLoopbackHostname(url.hostname))
	) {
		throw new Error(
			`${label}: issuer must be an https URL (plain http is accepted only on a loopback host), got ${issuer}`,
		);
	}
	return url;
}

function checkScopes(label: string, scopes: readonly string[] | undefined): readonly string[] {
	if (scopes === undefined) return [...DEFAULT_OIDC_SCOPES];
	if (!Array.isArray(scopes) || scopes.some((s) => typeof s !== "string" || s.length === 0)) {
		throw new Error(`${label}: scopes must be a list of non-empty strings`);
	}
	if (!scopes.includes("openid")) {
		throw new Error(
			`${label}: scopes must include "openid" — without it the IdP issues no id_token`,
		);
	}
	return [...scopes];
}

const REQUIRED_METADATA = ["authorization_endpoint", "token_endpoint", "jwks_uri"] as const;
const OVERRIDE_KEYS: ReadonlyArray<[keyof OidcEndpointOverrides, string]> = [
	["authorizationEndpoint", "authorization_endpoint"],
	["tokenEndpoint", "token_endpoint"],
	["jwksUri", "jwks_uri"],
	["userinfoEndpoint", "userinfo_endpoint"],
	["endSessionEndpoint", "end_session_endpoint"],
];

async function resolveServerMetadata(
	label: string,
	issuerUrl: URL,
	config: OidcProviderConfig,
	clientMetadata: Partial<oidc.ClientMetadata>,
	clientAuth: oidc.ClientAuth,
	insecure: boolean,
): Promise<oidc.ServerMetadata> {
	const overrides = config.endpoints ?? {};
	const mapped: Record<string, string> = {};
	for (const [key, metadataKey] of OVERRIDE_KEYS) {
		const value = overrides[key];
		if (value === undefined) continue;
		if (typeof value !== "string" || value.length === 0) {
			throw new Error(`${label}: endpoints.${key} must be a non-empty string`);
		}
		mapped[metadataKey] = value;
	}

	let metadata: oidc.ServerMetadata;
	if (config.discovery === false) {
		const missing = OVERRIDE_KEYS.slice(0, 3)
			.filter(([key]) => overrides[key] === undefined)
			.map(([key]) => `endpoints.${key}`);
		if (missing.length > 0) {
			throw new Error(`${label}: discovery is off, so ${missing.join(", ")} must be set`);
		}
		metadata = { issuer: config.issuer, ...mapped };
	} else {
		let discovered: oidc.Configuration;
		try {
			discovered = await oidc.discovery(issuerUrl, config.clientId, clientMetadata, clientAuth, {
				algorithm: "oidc",
				...(config.fetch
					? { [oidc.customFetch]: config.fetch as unknown as oidc.CustomFetch }
					: {}),
				...(insecure ? { execute: [oidc.allowInsecureRequests] } : {}),
			});
		} catch (err) {
			throw new Error(
				`${label}: discovery of ${config.issuer} failed and the provider cannot start without the issuer's metadata ` +
					`(set discovery = false and the endpoints to run from hand-typed values): ${message(err)}`,
				{ cause: err },
			);
		}
		// The helper methods on the discovered object do not survive a spread; the data does.
		const base = JSON.parse(JSON.stringify(discovered.serverMetadata())) as oidc.ServerMetadata;
		metadata = { ...base, ...mapped };
	}

	for (const key of REQUIRED_METADATA) {
		if (typeof metadata[key] !== "string") {
			throw new Error(
				`${label}: the issuer's metadata has no ${key}; the provider cannot ${key === "jwks_uri" ? "verify id_tokens" : "run"} without it (set endpoints to override)`,
			);
		}
	}
	return metadata;
}

export async function createOidcProvider(
	name: string,
	config: OidcProviderConfig,
): Promise<OidcProvider> {
	checkFederationName(name);
	const label = `OIDC federation "${name}"`;
	const issuerUrl = parseIssuer(label, config.issuer);
	const insecure = issuerUrl.protocol === "http:";
	if (typeof config.clientId !== "string" || config.clientId.length === 0) {
		throw new Error(`${label}: clientId is required`);
	}
	if (typeof config.callbackURL !== "string" || config.callbackURL.length === 0) {
		throw new Error(`${label}: callbackURL is required`);
	}
	const scopes = checkScopes(label, config.scopes);
	const clientAuth = await clientAuthFor(label, config);
	const clientMetadata: Partial<oidc.ClientMetadata> = {
		...(config.idTokenSignedResponseAlg
			? { id_token_signed_response_alg: config.idTokenSignedResponseAlg }
			: {}),
		...(config.clockToleranceSeconds !== undefined
			? { [oidc.clockTolerance]: config.clockToleranceSeconds }
			: {}),
	};

	const metadata = await resolveServerMetadata(
		label,
		issuerUrl,
		config,
		clientMetadata,
		clientAuth,
		insecure,
	);
	const configuration = new oidc.Configuration(
		metadata,
		config.clientId,
		clientMetadata,
		clientAuth,
	);
	if (config.fetch) configuration[oidc.customFetch] = config.fetch as unknown as oidc.CustomFetch;
	if (insecure) oidc.allowInsecureRequests(configuration);
	// openid-client 6 treats an id_token from the token endpoint as delivered
	// over TLS and skips its signature by default. The issue asks for
	// verification against the issuer's JWKS with rotation, and that is what
	// this switches on: the key is looked up by `kid`, the set is cached and
	// refetched when an unknown `kid` appears.
	oidc.enableNonRepudiationChecks(configuration);

	const hasUserInfo = typeof metadata.userinfo_endpoint === "string";
	if (config.userInfo === true && !hasUserInfo) {
		throw new Error(
			`${label}: userInfo = true but the issuer publishes no userinfo_endpoint (set endpoints.userinfoEndpoint, or drop userInfo)`,
		);
	}
	const useUserInfo = config.userInfo ?? hasUserInfo;
	const endSessionEndpoint = optionalString(metadata.end_session_endpoint);

	const requireNonce = (nonce: unknown): string => {
		if (typeof nonce !== "string" || nonce.length === 0) {
			throw new Error(
				`${label} requires a non-empty nonce — OIDC Core §3.1.3.7 binds the id_token to the session through it.`,
			);
		}
		return nonce;
	};

	const snapshot = (
		tokens: oidc.TokenEndpointResponse & oidc.TokenEndpointResponseHelpers,
	): Pick<FederationProfile, "accessToken" | "refreshToken" | "idToken" | "expiresAt"> => {
		const expiresIn = tokens.expiresIn();
		return {
			accessToken: tokens.access_token,
			refreshToken: optionalString(tokens.refresh_token),
			idToken: optionalString(tokens.id_token),
			expiresAt: typeof expiresIn === "number" ? new Date(Date.now() + expiresIn * 1000) : null,
		};
	};

	const endSession = async (req: EndSessionRequest): Promise<EndSessionResult> => {
		const url = oidc.buildEndSessionUrl(configuration, {
			...(req.idTokenHint ? { id_token_hint: req.idTokenHint } : {}),
			...(req.postLogoutRedirectUri ? { post_logout_redirect_uri: req.postLogoutRedirectUri } : {}),
			...(req.state ? { state: req.state } : {}),
		});
		return { url, method: "GET" };
	};

	return {
		name,
		scope: scopes,

		buildAuthorizationUrl(params): URL {
			const nonce = requireNonce(params.nonce);
			return oidc.buildAuthorizationUrl(configuration, {
				redirect_uri: params.redirectUri,
				scope: scopes.join(" "),
				state: params.state,
				code_challenge: codeChallenge(params.codeVerifier),
				code_challenge_method: "S256",
				nonce,
			});
		},

		async exchangeCode(params): Promise<FederationProfile> {
			const nonce = requireNonce(params.nonce);
			const callbackUrl = new URL(params.redirectUri);
			callbackUrl.searchParams.set("code", params.code);

			const tokens = await oidc.authorizationCodeGrant(configuration, callbackUrl, {
				pkceCodeVerifier: params.codeVerifier,
				// `state` was already compared against the session by the route.
				expectedState: oidc.skipStateCheck,
				expectedNonce: nonce,
				idTokenExpected: true,
			});
			const claims = tokens.claims();
			if (!claims) throw new Error(`${label}: the token response carried no id_token`);
			const sub = claims.sub;
			if (typeof sub !== "string" || sub.length === 0) {
				throw new Error(`${label}: id_token has no sub claim (OIDC Core §2)`);
			}
			if (claims.at_hash !== undefined) {
				verifyAtHash(label, tokens.id_token ?? "", tokens.access_token, claims.at_hash);
			}

			const info = useUserInfo
				? await oidc.fetchUserInfo(configuration, tokens.access_token, sub)
				: undefined;
			const pick = (key: string): unknown =>
				(info as Record<string, unknown> | undefined)?.[key] ??
				(claims as Record<string, unknown>)[key];
			const groups = stringArray(pick("groups"));

			return {
				issuer: claims.iss,
				sub,
				email: optionalString(pick("email")),
				emailVerified: optionalBoolean(pick("email_verified")),
				name: optionalString(pick("name")),
				picture: optionalString(pick("picture")),
				...snapshot(tokens),
				...(groups ? { groups } : {}),
			};
		},

		async refreshToken(refreshTokenValue: string): Promise<RefreshedTokens> {
			return snapshot(await oidc.refreshTokenGrant(configuration, refreshTokenValue));
		},

		mapClaims(profile: FederationProfile): MappedClaims {
			const claims: Record<string, unknown> = {};
			if (typeof profile.email === "string") claims.email = profile.email;
			if (typeof profile.emailVerified === "boolean") claims.emailVerified = profile.emailVerified;
			if (typeof profile.name === "string") claims.name = profile.name;
			if (typeof profile.picture === "string") claims.picture = profile.picture;
			const groups = stringArray(profile.groups);
			if (groups) claims.groups = groups;
			return claims as MappedClaims;
		},

		...(endSessionEndpoint ? { endSession } : {}),
	};
}
