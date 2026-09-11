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

/**
 * A fake OpenID Provider behind a `fetch` implementation (#524).
 *
 * The provider under test is handed `idp.fetch` through its `fetch` option,
 * which openid-client uses for every request it makes — discovery, JWKS,
 * token, userinfo — so nothing here touches the network and every request
 * is recorded for the tests to inspect. The IdP signs real RS256 id_tokens
 * under a key it publishes at `jwks_uri`; the knobs below let a test make
 * it misbehave in exactly one way at a time.
 */
export interface FakeIdpOptions {
	readonly issuer: string;
	readonly clientId?: string;
	readonly sub?: string;
	/** Publish an `end_session_endpoint`. Default: no. */
	readonly endSession?: boolean;
	/** Publish a `userinfo_endpoint`. Default: yes. */
	readonly userinfo?: boolean;
}

export interface RecordedRequest {
	readonly url: URL;
	readonly method: string;
	readonly headers: Headers;
	readonly body: URLSearchParams | undefined;
}

export interface FakeIdp {
	readonly issuer: string;
	readonly clientId: string;
	readonly sub: string;
	readonly requests: RecordedRequest[];
	readonly fetch: typeof fetch;
	/** The discovery document. Mutable, so a test can corrupt one field. */
	readonly metadata: Record<string, unknown>;
	/** Claims laid over the id_token defaults. */
	idTokenClaims: Record<string, unknown>;
	/** The nonce the next id_token echoes; absent when undefined. */
	nonce: string | undefined;
	/** Sign under the current key but claim this `kid` in the header. */
	signingKid: string | undefined;
	/** Leave the id_token out of the token response. */
	omitIdToken: boolean;
	/** Whether the id_token carries `at_hash`, and whether it is right. */
	atHash: "none" | "valid" | "wrong";
	/** Claims laid over the userinfo defaults. */
	userinfoClaims: Record<string, unknown>;
	discoveryStatus: number;
	tokenStatus: number;
	accessToken: string;
	/** Replace the signing key; the JWKS then holds only the new one. */
	rotateKey(): Promise<string>;
	currentKid(): string;
	requestsTo(path: string): RecordedRequest[];
	lastTokenRequest(): RecordedRequest | undefined;
}

function json(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "content-type": "application/json" },
	});
}

/** OIDC Core §3.3.2.11 for an RS256 id_token: SHA-256, left half, base64url. */
export function sha256LeftHalf(value: string): string {
	const digest = createHash("sha256").update(value).digest();
	return digest.subarray(0, digest.length / 2).toString("base64url");
}

export async function createFakeIdp(options: FakeIdpOptions): Promise<FakeIdp> {
	const issuer = options.issuer.replace(/\/$/, "");
	const clientId = options.clientId ?? "client-under-test";
	const sub = options.sub ?? "user-0001";

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

	const metadata: Record<string, unknown> = {
		issuer,
		authorization_endpoint: `${issuer}/authorize`,
		token_endpoint: `${issuer}/token`,
		jwks_uri: `${issuer}/jwks`,
		...(options.userinfo === false ? {} : { userinfo_endpoint: `${issuer}/userinfo` }),
		...(options.endSession ? { end_session_endpoint: `${issuer}/logout` } : {}),
		response_types_supported: ["code"],
		subject_types_supported: ["public"],
		id_token_signing_alg_values_supported: ["RS256"],
		token_endpoint_auth_methods_supported: ["client_secret_basic", "private_key_jwt"],
		code_challenge_methods_supported: ["S256"],
	};

	const requests: RecordedRequest[] = [];

	const idp: FakeIdp = {
		issuer,
		clientId,
		sub,
		requests,
		metadata,
		idTokenClaims: {},
		nonce: undefined,
		signingKid: undefined,
		omitIdToken: false,
		atHash: "none",
		userinfoClaims: {},
		discoveryStatus: 200,
		tokenStatus: 200,
		accessToken: "at-1",
		fetch: undefined as unknown as typeof fetch,
		rotateKey: newKey,
		currentKid: () => signer.kid,
		requestsTo: (path) => requests.filter((r) => r.url.href === `${issuer}${path}`),
		lastTokenRequest: () => requests.filter((r) => r.url.href === `${issuer}/token`).at(-1),
	};

	const mintIdToken = async (): Promise<string> => {
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
			...(idp.nonce === undefined ? {} : { nonce: idp.nonce }),
			...(idp.atHash === "none"
				? {}
				: {
						at_hash:
							idp.atHash === "valid" ? sha256LeftHalf(idp.accessToken) : "AAAAAAAAAAAAAAAAAAAAAA",
					}),
			...idp.idTokenClaims,
		};
		return new SignJWT(claims)
			.setProtectedHeader({ alg: "RS256", kid: idp.signingKid ?? signer.kid })
			.sign(signer.key);
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
			(init?.headers ?? (input instanceof Request ? input.headers : undefined)) as HeadersInit,
		);
		const raw = init?.body;
		const body =
			raw === undefined || raw === null
				? undefined
				: new URLSearchParams(raw instanceof URLSearchParams ? raw : String(raw));
		requests.push({ url, method, headers, body });

		const path = url.href.startsWith(`${issuer}/`) ? url.href.slice(issuer.length) : url.href;
		if (path === "/.well-known/openid-configuration") return json(metadata, idp.discoveryStatus);
		if (path === "/jwks") return json(jwks);
		if (path === "/token" && method === "POST") {
			if (idp.tokenStatus !== 200) return json({ error: "invalid_client" }, idp.tokenStatus);
			if (body?.get("grant_type") === "refresh_token") {
				return json({
					access_token: "at-refreshed",
					token_type: "Bearer",
					expires_in: 1800,
					refresh_token: "rt-2",
				});
			}
			return json({
				access_token: idp.accessToken,
				token_type: "Bearer",
				expires_in: 3600,
				refresh_token: "rt-1",
				...(idp.omitIdToken ? {} : { id_token: await mintIdToken() }),
			});
		}
		if (path === "/userinfo") {
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
