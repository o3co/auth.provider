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

import { AsyncLocalStorage } from "node:async_hooks";
import { isLoopbackHostname } from "@o3co/auth-provider-core";
import {
	callbackUrlForExchange,
	codeChallenge,
	type DelegatedAuthorizationRequest,
	type DelegatedAuthorizationResult,
	type DelegatedCodeExchangeRequest,
	type DelegatedRefreshRequest,
	type DelegatedTokens,
	type EndSessionRequest,
	type EndSessionResult,
	type FederationClientSecret,
	type FederationProfile,
	type FederationProvider,
	type MappedClaims,
	RESERVED_DELEGATED_AUTHORIZATION_PARAMS,
	type RefreshedTokens,
	type SupportsClaimMapping,
	type SupportsDelegatedAuthorization,
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
	SupportsDelegatedAuthorization &
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

/**
 * The authorization parameters this provider owns (#593, D17). An operator's
 * `authorizationParams` may not name them: openid-client sets `client_id` and
 * `response_type` only when absent, so a copied parameter would send the
 * consent to another registration or select a flow the callback cannot
 * consume; `scope` is the intent's; `resource` is a field of its own, so that
 * authorization and refresh never disagree about it; a request object or a
 * response mode would change what comes back to the callback.
 */
/**
 * What a delegated refresh hands its fetch, for the duration of one library
 * call: the caller's signal, and a place for the token endpoint's raw body.
 * openid-client takes no per-call signal, and reads the body before it
 * returns it — so the fetch that carries the request is where both live. One
 * `Configuration` serves every call, JWKS cache included; what differs per
 * call travels here instead.
 */
interface DelegatedCall {
	readonly signal?: AbortSignal;
	captured?: Record<string, unknown>;
	/** When the token endpoint's answer arrived: what dates the token, before any verification the library does. */
	receivedAt?: number;
}
const delegatedCalls = new AsyncLocalStorage<DelegatedCall>();

/** The same endpoint however it is spelled: oauth4webapi normalizes the URL it fetches (a default port, a trailing dot). */
const sameEndpoint = (fetched: string, configured: string): boolean => {
	try {
		return new URL(fetched).href === new URL(configured).href;
	} catch {
		return fetched === configured;
	}
};

/**
 * The lifetime the upstream SENT, judged before the library's coercion: it
 * applies `parseFloat` to whatever it finds, so `[3600, 7200]` reads as 3600
 * and "1000seconds" as 1000, and neither is a lifetime an operator's maximum
 * can be held against (D5). A number is one; so is a string of digits, which
 * some IdPs send; nothing else. Without a captured body the coerced value is
 * all there is.
 */
const rawLifetime = (
	captured: Record<string, unknown> | undefined,
	coerced: number | undefined,
): { readonly ok: true; readonly seconds: number | null } | { readonly ok: false } => {
	if (captured === undefined) {
		return { ok: true, seconds: typeof coerced === "number" ? coerced : null };
	}
	const raw = captured.expires_in;
	if (raw === undefined) return { ok: true, seconds: null };
	if (typeof raw === "number" && Number.isFinite(raw)) return { ok: true, seconds: raw };
	if (typeof raw === "string" && /^\d+$/.test(raw)) return { ok: true, seconds: Number(raw) };
	return { ok: false };
};

/** The raw JSON of a token endpoint's answer, when it is one; anything else is nobody's to salvage from. */
const readTokenBody = async (response: Response): Promise<Record<string, unknown> | undefined> => {
	try {
		if (response.status !== 200) return undefined;
		const parsed: unknown = await response.clone().json();
		return typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)
			? (parsed as Record<string, unknown>)
			: undefined;
	} catch {
		return undefined;
	}
};

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
	// `OidcClientAuth` is `oidc.ClientAuth` kept out of the public declarations.
	const clientAuth = (await clientAuthFor(label, config)) as oidc.ClientAuth;
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
	// Every request the library makes goes through here. Outside a delegated
	// refresh it is the configured fetch, or the global one, exactly as before.
	// Inside one, the caller's signal is combined with the library's own, and
	// the token endpoint's body is kept so that a rotated refresh token is not
	// lost to a parser that refuses the rest of the answer (D5).
	const baseFetch: typeof fetch = config.fetch ?? fetch;
	const tokenEndpoint = optionalString(metadata.token_endpoint);
	const delegatedFetch: oidc.CustomFetch = async (url, options) => {
		const call = delegatedCalls.getStore();
		if (call === undefined) return baseFetch(url, options);
		const signals = [options?.signal, call.signal].filter(
			(candidate): candidate is AbortSignal => candidate instanceof AbortSignal,
		);
		const response = await baseFetch(url, {
			...options,
			...(signals.length > 0 ? { signal: AbortSignal.any(signals) } : {}),
		});
		if (tokenEndpoint !== undefined && sameEndpoint(String(url), tokenEndpoint)) {
			call.receivedAt = Date.now();
			call.captured = await readTokenBody(response);
		}
		return response;
	};
	configuration[oidc.customFetch] = delegatedFetch;
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
	): Pick<
		FederationProfile,
		"accessToken" | "refreshToken" | "idToken" | "expiresAt" | "expiresIn" | "scope" | "tokenType"
	> => {
		// `expiresIn()` counts down from when the response arrived; the login
		// flow's expiry has always been derived from it, and stays so. The raw
		// `expires_in` beside it is what a rule that judges the issued lifetime
		// reads (#593, D5).
		const expiresIn = tokens.expiresIn();
		const issued = tokens.expires_in;
		return {
			accessToken: tokens.access_token,
			refreshToken: optionalString(tokens.refresh_token),
			idToken: optionalString(tokens.id_token),
			expiresAt: typeof expiresIn === "number" ? new Date(Date.now() + expiresIn * 1000) : null,
			expiresIn: typeof issued === "number" ? issued : null,
			...(optionalString(tokens.scope) !== undefined ? { scope: tokens.scope } : {}),
			tokenType: tokens.token_type,
		};
	};

	const delegatedAuthorizationUrl = (params: DelegatedAuthorizationRequest): URL => {
		const nonce = requireNonce(params.nonce);
		const scopes = params.scopes;
		if (!Array.isArray(scopes) || scopes.some((s) => typeof s !== "string" || s.length === 0)) {
			throw new Error(`${label}: delegated scopes must be a list of non-empty strings`);
		}
		if (!scopes.includes("openid")) {
			throw new Error(
				`${label}: delegated scopes must include "openid" — without it the IdP issues no id_token`,
			);
		}
		const extra = params.authorizationParams ?? {};
		for (const [key, value] of Object.entries(extra)) {
			if (RESERVED_DELEGATED_AUTHORIZATION_PARAMS.has(key)) {
				throw new Error(
					`${label}: authorizationParams may not set "${key}" — this provider owns it (#593, D17)`,
				);
			}
			// A value that is not a string would be sent spelled out ("undefined"),
			// and an undefined prompt would defeat the consent default below.
			if (typeof value !== "string") {
				throw new Error(`${label}: authorizationParams "${key}" must be a string`);
			}
		}
		return oidc.buildAuthorizationUrl(configuration, {
			// OIDC Core §11: offline_access is ignored unless the user is prompted
			// for consent. An operator's own prompt wins.
			...(scopes.includes("offline_access") && extra.prompt === undefined
				? { prompt: "consent" }
				: {}),
			...extra,
			...(params.resource !== undefined ? { resource: params.resource } : {}),
			redirect_uri: params.redirectUri,
			scope: scopes.join(" "),
			state: params.state,
			code_challenge: codeChallenge(params.codeVerifier),
			code_challenge_method: "S256",
			nonce,
		});
	};

	const refreshDelegated = async (params: DelegatedRefreshRequest): Promise<DelegatedTokens> => {
		const call: DelegatedCall = { ...(params.signal ? { signal: params.signal } : {}) };
		const body = {
			...(params.scopes !== undefined && params.scopes.length > 0
				? { scope: params.scopes.join(" ") }
				: {}),
			...(params.resource !== undefined ? { resource: params.resource } : {}),
		};
		let tokens: oidc.TokenEndpointResponse & oidc.TokenEndpointResponseHelpers;
		try {
			tokens = await delegatedCalls.run(call, () =>
				oidc.refreshTokenGrant(configuration, params.refreshToken, body),
			);
		} catch (error) {
			// An answer the library could not parse may still carry a rotated
			// refresh token, and that one is never lost (D5). Only a 200 is ever
			// captured: the IdP's own refusal is a 4xx, has nothing to salvage
			// from whatever its body says, and is rethrown for the classifier.
			const rotated = optionalString(call.captured?.refresh_token);
			if (rotated === undefined) throw error;
			return { refreshToken: rotated };
		}
		const rotated = optionalString(tokens.refresh_token);
		const lifetime = rawLifetime(call.captured, tokens.expires_in);
		// A lifetime that is not one withholds the access token — core marks
		// the answer malformed — and keeps the rotated refresh token (D5).
		if (!lifetime.ok) return rotated !== undefined ? { refreshToken: rotated } : {};
		// Dated when the answer ARRIVED, on this adapter's clock: the library
		// may have gone on to verify an id_token against a JWKS it had to fetch,
		// and that time is not the token's (#593, D17).
		const obtainedAt = call.receivedAt ?? Date.now();
		return {
			accessToken: tokens.access_token,
			...(rotated !== undefined ? { refreshToken: rotated } : {}),
			expiresIn: lifetime.seconds,
			expiresAt: lifetime.seconds !== null ? new Date(obtainedAt + lifetime.seconds * 1000) : null,
			...(optionalString(tokens.scope) !== undefined ? { scope: tokens.scope } : {}),
			tokenType: tokens.token_type,
		};
	};

	/**
	 * The connect callback's exchange (#593, D7, D17). It shares the refresh's
	 * capture of the raw answer — the lifetime the upstream SENT, dated at
	 * receipt — and none of the login exchange's profile work: no UserInfo, no
	 * claim mapping. The identity is the verified id_token's, and only that.
	 *
	 * What it does NOT share with the refresh is the salvage. A refresh keeps a
	 * rotated refresh token out of an answer the library refused to parse,
	 * because the grant it rotates already exists. An acquisition whose answer
	 * could not be verified has no grant, and no identity to bind one to; the
	 * failure is thrown whole.
	 */
	const exchangeDelegated = async (
		params: DelegatedCodeExchangeRequest,
	): Promise<DelegatedAuthorizationResult> => {
		const nonce = requireNonce(params.nonce);
		const callbackUrl = callbackUrlForExchange({
			redirectUri: params.redirectUri,
			code: params.code,
			callbackParams: params.callbackParams,
		});
		const call: DelegatedCall = { ...(params.signal ? { signal: params.signal } : {}) };
		const tokens = await delegatedCalls.run(call, () =>
			oidc.authorizationCodeGrant(
				configuration,
				callbackUrl,
				{
					pkceCodeVerifier: params.codeVerifier,
					// `state` was compared against the connect transaction by the route.
					expectedState: oidc.skipStateCheck,
					expectedNonce: nonce,
					idTokenExpected: true,
				},
				params.resource !== undefined ? { resource: params.resource } : undefined,
			),
		);
		const claims = tokens.claims();
		if (!claims) throw new Error(`${label}: the token response carried no id_token`);
		const subject = claims.sub;
		if (typeof subject !== "string" || subject.length === 0) {
			throw new Error(`${label}: id_token has no sub claim (OIDC Core §2)`);
		}
		if (claims.at_hash !== undefined) {
			verifyAtHash(label, tokens.id_token ?? "", tokens.access_token, claims.at_hash);
		}
		const upstream = { issuer: claims.iss, subject };
		const refreshToken = optionalString(tokens.refresh_token);
		const lifetime = rawLifetime(call.captured, tokens.expires_in);
		// A lifetime that is not one withholds the access token — core then reads
		// the answer as malformed and refuses the activation (D5) — as a refresh
		// does. The identity above was verified, so it is still reported.
		if (!lifetime.ok) {
			return { upstream, tokens: refreshToken !== undefined ? { refreshToken } : {} };
		}
		const obtainedAt = call.receivedAt ?? Date.now();
		return {
			upstream,
			tokens: {
				accessToken: tokens.access_token,
				...(refreshToken !== undefined ? { refreshToken } : {}),
				expiresIn: lifetime.seconds,
				expiresAt:
					lifetime.seconds !== null ? new Date(obtainedAt + lifetime.seconds * 1000) : null,
				...(optionalString(tokens.scope) !== undefined ? { scope: tokens.scope } : {}),
				tokenType: tokens.token_type,
			},
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
			// #595: RFC 9207. The library compares `iss` with the configured issuer,
			// and requires one from an issuer that advertises
			// `authorization_response_iss_parameter_supported` — so dropping it both
			// skips the mix-up check and fails every login against such an issuer.
			// `callbackUrlForExchange` forwards `iss` and nothing else from the bag,
			// and says why. `state` never reaches an adapter, and `skipStateCheck`
			// ignores it.
			const callbackUrl = callbackUrlForExchange({
				redirectUri: params.redirectUri,
				code: params.code,
				callbackParams: params.callbackParams,
			});

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

		buildDelegatedAuthorizationUrl: delegatedAuthorizationUrl,
		exchangeDelegatedCode: exchangeDelegated,
		refreshDelegatedToken: refreshDelegated,

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
