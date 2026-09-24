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

import { createHash } from "node:crypto";
import { type CryptoKey, exportJWK, generateKeyPair, type JWK, SignJWT } from "jose";
import { readSpaceDelimitedParameter } from "../federations/scope.mjs";

/**
 * A fake OpenID Provider behind a `fetch` implementation (#542).
 *
 * The provider under test is handed `idp.fetch` through its `fetch` option,
 * which openid-client uses for every request it makes — discovery, JWKS,
 * token, userinfo — so nothing here touches the network and every request is
 * recorded for the tests to inspect. The IdP signs real RS256 id_tokens under
 * a key it publishes at its JWKS URI; the knobs below let a test make it
 * misbehave in exactly one way at a time.
 *
 * One harness for the OpenID Connect adapters — Google, Apple and the generic
 * OIDC one — so they are held to one fake rather than to copies that drift.
 * (GitHub is not an OpenID Provider; its tests run on its own fake GitHub.)
 * Endpoints may be named explicitly — Google's and Apple's are not paths
 * under the issuer, and those providers build their metadata locally — or
 * left to default to paths under the issuer, with `discovery` serving the
 * document a discovering provider (federation-oidc) reads at boot.
 */
export interface FakeIdpOptions {
	readonly issuer: string;
	/** Default: `<issuer>/token`. */
	readonly tokenEndpoint?: string;
	/** Default: `<issuer>/jwks`. */
	readonly jwksUri?: string;
	/** Absent for a provider that publishes none (Apple). */
	readonly userinfoEndpoint?: string;
	/** Where `authorize` accepts an authorization request. Default: `<issuer>/authorize`. */
	readonly authorizationEndpoint?: string;
	/** Named in the discovery document only; nothing is served there. */
	readonly endSessionEndpoint?: string;
	/** Serve `metadata` at `<issuer>/.well-known/openid-configuration`. Default: no. */
	readonly discovery?: boolean;
	readonly clientId?: string;
	readonly sub?: string;
}

/** What the user agent carries back to the callback from `authorize`. */
export interface FakeIdpAuthorizationResponse {
	readonly code: string;
	readonly state: string | null;
	/** RFC 9207: the issuer, as an IdP that advertises the parameter sends it. */
	readonly iss: string;
}

export interface FakeIdpRequest {
	readonly url: URL;
	readonly method: string;
	readonly headers: Headers;
	readonly body: URLSearchParams | undefined;
}

export interface FakeIdp {
	readonly issuer: string;
	readonly clientId: string;
	readonly sub: string;
	readonly requests: FakeIdpRequest[];
	readonly fetch: typeof fetch;
	/**
	 * The discovery document, served when `discovery` is on. Mutable, so a
	 * test can corrupt one field or add one (`authorization_response_iss_
	 * parameter_supported`) before the provider under test discovers it.
	 */
	readonly metadata: Record<string, unknown>;
	/** The status the discovery document is answered with. */
	discoveryStatus: number;
	/** Claims laid over the id_token defaults. */
	idTokenClaims: Record<string, unknown>;
	/**
	 * The nonce a code exchange's id_token echoes for a code `authorize()` did
	 * NOT issue; absent when undefined. A code `authorize()` issued carries its
	 * own authorization's nonce, whatever this says.
	 */
	nonce: string | undefined;
	/** Sign under the current key but claim this `kid` in the header. */
	signingKid: string | undefined;
	/**
	 * Sign under a key that was never published, claiming the published `kid`.
	 * A valid RS256 signature by the wrong key: the case only a signature
	 * check against the JWKS can catch.
	 */
	signWithUnpublishedKey: boolean;
	/** Leave the id_token out of the token responses — the code exchange's and the refresh's. */
	omitIdToken: boolean;
	/**
	 * Whether a refresh answer carries an id_token. Default `true`: Google and
	 * Apple re-issue one, and the library verifies it like the login's.
	 */
	refreshWithIdToken: boolean;
	/** Whether the code exchange's id_token carries `at_hash`, and whether it is right. */
	atHash: "none" | "valid" | "wrong";
	/** Claims laid over the userinfo defaults. */
	userinfoClaims: Record<string, unknown>;
	tokenStatus: number;
	/** The body of a token-endpoint refusal (when `tokenStatus` is not 200). */
	refusal: Record<string, unknown>;
	accessToken: string;
	/**
	 * Laid over the code exchange's answer; a value of `undefined` removes the
	 * field. Lets a test make the answer omit `expires_in`, carry a `scope`,
	 * or carry a field of the wrong shape.
	 */
	codeAnswer: Record<string, unknown>;
	/** Laid over the refresh answer, as `codeAnswer` is over the code exchange's. */
	refreshAnswer: Record<string, unknown>;
	/** How long the JWKS takes to answer, in real milliseconds. */
	jwksDelayMs: number;
	/**
	 * Google's documented rule for a code `authorize` issued: the exchange
	 * carries a `refresh_token` only when the authorization asked for
	 * `access_type=offline` AND the user was shown the consent screen — the
	 * first time this client asks this user, or whenever `prompt` includes
	 * `consent`. Default `false`: every exchange carries one.
	 */
	refreshTokenOnlyOnConsent: boolean;
	/**
	 * Play the user agent and the user at the authorization endpoint: accept
	 * the authorization request `url` names (its client, redirect URI, PKCE
	 * challenge and nonce are recorded, and that code's id_token echoes that
	 * nonce), approve it, and answer what the IdP redirects back with. The
	 * token endpoint then holds the exchange of that code to the recorded
	 * request: the same redirect URI, a verifier that matches the challenge,
	 * one use — a second exchange is `invalid_grant`.
	 */
	authorize(url: URL | string): FakeIdpAuthorizationResponse;
	/** Replace the signing key; the JWKS then holds only the new one. */
	rotateKey(): Promise<string>;
	currentKid(): string;
	/**
	 * Requests to an endpoint — an absolute URL, or a path under the issuer
	 * (`"/token"`) — compared on origin and path (a query string is ignored).
	 */
	requestsTo(endpoint: string): FakeIdpRequest[];
	/** The last request to the token endpoint. */
	lastTokenRequest(): FakeIdpRequest | undefined;
}

/** The defaults with the overlay laid over them, and every field the overlay set to `undefined` gone. */
const overlaid = (
	defaults: Record<string, unknown>,
	overlay: Record<string, unknown>,
): Record<string, unknown> =>
	Object.fromEntries(
		Object.entries({ ...defaults, ...overlay }).filter(([, value]) => value !== undefined),
	);

function json(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "content-type": "application/json" },
	});
}

/**
 * Where a request goes: origin and path, the host without the DNS root dot.
 * `idp.test.` and `idp.test` resolve to the same server, so a request that
 * carries the dot reaches this IdP too.
 */
const originAndPath = (url: URL): string => {
	const routed = new URL(url.href);
	routed.hostname = routed.hostname.replace(/\.$/, "");
	return `${routed.origin}${routed.pathname}`;
};

/** OIDC Core §3.3.2.11 for an RS256 id_token: SHA-256, left half, base64url. */
const sha256LeftHalf = (value: string): string => {
	const digest = createHash("sha256").update(value).digest();
	return digest.subarray(0, digest.length / 2).toString("base64url");
};

export async function createFakeIdp(options: FakeIdpOptions): Promise<FakeIdp> {
	const issuer = options.issuer.replace(/\/$/, "");
	const clientId = options.clientId ?? "client-under-test";
	const sub = options.sub ?? "user-0001";
	const urls = {
		authorization: options.authorizationEndpoint ?? `${issuer}/authorize`,
		token: options.tokenEndpoint ?? `${issuer}/token`,
		jwks: options.jwksUri ?? `${issuer}/jwks`,
		userinfo: options.userinfoEndpoint,
		discovery: `${issuer}/.well-known/openid-configuration`,
	};
	const endpoints = {
		authorization: originAndPath(new URL(urls.authorization)),
		token: originAndPath(new URL(urls.token)),
		jwks: originAndPath(new URL(urls.jwks)),
		userinfo: urls.userinfo === undefined ? undefined : originAndPath(new URL(urls.userinfo)),
		discovery: options.discovery ? originAndPath(new URL(urls.discovery)) : undefined,
	};
	/** A path under the issuer (`"/token"`) or an absolute URL, as the endpoint it names. */
	const endpointOf = (endpoint: string): string =>
		originAndPath(new URL(endpoint.startsWith("/") ? `${issuer}${endpoint}` : endpoint));

	const metadata: Record<string, unknown> = {
		issuer,
		authorization_endpoint: urls.authorization,
		token_endpoint: urls.token,
		jwks_uri: urls.jwks,
		...(urls.userinfo === undefined ? {} : { userinfo_endpoint: urls.userinfo }),
		...(options.endSessionEndpoint === undefined
			? {}
			: { end_session_endpoint: options.endSessionEndpoint }),
		response_types_supported: ["code"],
		subject_types_supported: ["public"],
		id_token_signing_alg_values_supported: ["RS256"],
		token_endpoint_auth_methods_supported: ["client_secret_basic", "private_key_jwt"],
		code_challenge_methods_supported: ["S256"],
	};

	/** The authorization request behind each code `authorize` issued, until it is exchanged. */
	const authorizations = new Map<
		string,
		{ readonly params: URLSearchParams; readonly consentShown: boolean }
	>();
	/** Codes `authorize` issued that have been exchanged: a second exchange is refused. */
	const spentCodes = new Set<string>();
	let codesIssued = 0;
	/** Whether this client has been granted consent by this user before. */
	let consentGranted = false;

	let keyIndex = 0;
	let signer: { kid: string; key: CryptoKey } = { kid: "", key: undefined as unknown as CryptoKey };
	const jwks: { keys: JWK[] } = { keys: [] };
	const newKey = async (): Promise<string> => {
		const { publicKey, privateKey } = await generateKeyPair("RS256");
		keyIndex += 1;
		const kid = `kid-${keyIndex}`;
		jwks.keys = [{ ...(await exportJWK(publicKey)), kid, use: "sig", alg: "RS256" }];
		signer = { kid, key: privateKey };
		return kid;
	};
	await newKey();

	const requests: FakeIdpRequest[] = [];
	const requestsTo = (endpoint: string): FakeIdpRequest[] => {
		const wanted = endpointOf(endpoint);
		return requests.filter((r) => originAndPath(r.url) === wanted);
	};

	const idp: FakeIdp = {
		issuer,
		clientId,
		sub,
		requests,
		metadata,
		discoveryStatus: 200,
		idTokenClaims: {},
		nonce: undefined,
		signingKid: undefined,
		signWithUnpublishedKey: false,
		omitIdToken: false,
		refreshWithIdToken: true,
		atHash: "none",
		userinfoClaims: {},
		tokenStatus: 200,
		refusal: { error: "invalid_client" },
		accessToken: "at-1",
		codeAnswer: {},
		refreshAnswer: {},
		jwksDelayMs: 0,
		refreshTokenOnlyOnConsent: false,
		authorize: (input) => {
			const url = new URL(input);
			if (originAndPath(url) !== endpoints.authorization) {
				throw new Error(`fake IdP: ${originAndPath(url)} is not its authorization endpoint`);
			}
			const params = url.searchParams;
			if (params.get("client_id") !== clientId) {
				throw new Error(`fake IdP: unknown client_id ${String(params.get("client_id"))}`);
			}
			// OIDC Core §3.1.2.1: space-delimited. Read as a real IdP reads it, and
			// refused when it is not, so an adapter that sent a malformed prompt
			// fails here rather than only against a real IdP.
			const prompts = readSpaceDelimitedParameter(params.get("prompt") ?? "");
			if (prompts === null) {
				throw new Error(
					`fake IdP: prompt ${JSON.stringify(params.get("prompt"))} is not a space-delimited list`,
				);
			}
			const consentShown = !consentGranted || prompts.includes("consent");
			consentGranted = true;
			codesIssued += 1;
			const code = `authorized-code-${codesIssued}`;
			authorizations.set(code, { params: new URLSearchParams(params), consentShown });
			return { code, state: params.get("state"), iss: issuer };
		},
		fetch: undefined as unknown as typeof fetch,
		rotateKey: newKey,
		currentKid: () => signer.kid,
		requestsTo,
		lastTokenRequest: () => requestsTo(urls.token).at(-1),
	};

	/**
	 * A refresh's id_token carries no nonce: there is no authorization request
	 * for it to echo. A code's carries the nonce of the authorization it came
	 * from, or — for a code `authorize` did not issue — `idp.nonce`. `at_hash`
	 * binds the code exchange's access token.
	 */
	const mintIdToken = async (
		opts: {
			readonly nonce: boolean;
			readonly authorizedNonce?: string | null;
			readonly accessToken?: string;
		} = { nonce: true },
	): Promise<string> => {
		const nonce = opts.authorizedNonce !== undefined ? opts.authorizedNonce : idp.nonce;
		const now = Math.floor(Date.now() / 1000);
		const claims: Record<string, unknown> = {
			iss: issuer,
			aud: clientId,
			sub,
			iat: now,
			exp: now + 300,
			email: "alice@example.test",
			email_verified: true,
			name: "Alice Example",
			...(opts.nonce && nonce !== undefined && nonce !== null ? { nonce } : {}),
			...(opts.accessToken === undefined || idp.atHash === "none"
				? {}
				: {
						at_hash:
							idp.atHash === "valid" ? sha256LeftHalf(opts.accessToken) : "AAAAAAAAAAAAAAAAAAAAAA",
					}),
			...idp.idTokenClaims,
		};
		const key = idp.signWithUnpublishedKey
			? (await generateKeyPair("RS256")).privateKey
			: signer.key;
		return new SignJWT(claims)
			.setProtectedHeader({ alg: "RS256", kid: idp.signingKid ?? signer.kid })
			.sign(key);
	};

	const fetchImpl = async (
		input: string | URL | Request,
		init?: RequestInit,
	): Promise<Response> => {
		const url = new URL(
			typeof input === "string" ? input : input instanceof URL ? input.href : input.url,
		);
		const method = (
			init?.method ?? (input instanceof Request ? input.method : "GET")
		).toUpperCase();
		const headers = new Headers(
			(init?.headers ??
				(input instanceof Request ? input.headers : undefined)) as ConstructorParameters<
				typeof Headers
			>[0],
		);
		const raw = init?.body;
		const body =
			raw === undefined || raw === null
				? undefined
				: new URLSearchParams(raw instanceof URLSearchParams ? raw : String(raw));
		requests.push({ url, method, headers, body });

		const where = originAndPath(url);
		if (endpoints.discovery !== undefined && where === endpoints.discovery) {
			return json(metadata, idp.discoveryStatus);
		}
		if (where === endpoints.jwks) {
			if (idp.jwksDelayMs > 0) await new Promise((resolve) => setTimeout(resolve, idp.jwksDelayMs));
			return json(jwks);
		}
		if (where === endpoints.token && method === "POST") {
			if (idp.tokenStatus !== 200) return json(idp.refusal, idp.tokenStatus);
			if (body?.get("grant_type") === "refresh_token") {
				return json(
					overlaid(
						{
							access_token: "at-refreshed",
							token_type: "Bearer",
							expires_in: 1800,
							refresh_token: "rt-2",
							...(idp.omitIdToken || !idp.refreshWithIdToken
								? {}
								: { id_token: await mintIdToken({ nonce: false }) }),
						},
						idp.refreshAnswer,
					),
				);
			}
			const code = body?.get("code") ?? "";
			if (spentCodes.has(code)) return json({ error: "invalid_grant" }, 400);
			const authorization = authorizations.get(code);
			let issueRefreshToken = true;
			if (authorization !== undefined) {
				// One use, the same redirect URI, and a verifier that matches the
				// challenge (RFC 6749 §4.1.3, RFC 7636 §4.6).
				authorizations.delete(code);
				spentCodes.add(code);
				const challenge = createHash("sha256")
					.update(body?.get("code_verifier") ?? "")
					.digest("base64url");
				if (
					body?.get("redirect_uri") !== authorization.params.get("redirect_uri") ||
					challenge !== authorization.params.get("code_challenge")
				) {
					return json({ error: "invalid_grant" }, 400);
				}
				if (idp.refreshTokenOnlyOnConsent) {
					issueRefreshToken =
						authorization.params.get("access_type") === "offline" && authorization.consentShown;
				}
			}
			return json(
				overlaid(
					{
						access_token: idp.accessToken,
						token_type: "Bearer",
						expires_in: 3600,
						...(issueRefreshToken ? { refresh_token: "rt-1" } : {}),
						...(idp.omitIdToken
							? {}
							: {
									id_token: await mintIdToken({
										nonce: true,
										...(authorization !== undefined
											? { authorizedNonce: authorization.params.get("nonce") }
											: {}),
										accessToken: idp.accessToken,
									}),
								}),
					},
					idp.codeAnswer,
				),
			);
		}
		if (endpoints.userinfo !== undefined && where === endpoints.userinfo) {
			return json({
				sub,
				email: "alice@example.test",
				email_verified: true,
				name: "Alice Example",
				picture: `${issuer}/alice.png`,
				...idp.userinfoClaims,
			});
		}
		return new Response("not found", { status: 404 });
	};
	(idp as { fetch: typeof fetch }).fetch = fetchImpl as typeof fetch;
	return idp;
}
