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

import { type CryptoKey, exportJWK, generateKeyPair, type JWK, SignJWT } from "jose";

/**
 * A fake OpenID Provider behind a `fetch` implementation (#542).
 *
 * The provider under test is handed `idp.fetch` through its `fetch` option,
 * which openid-client uses for every request it makes — JWKS, token,
 * userinfo — so nothing here touches the network and every request is
 * recorded for the tests to inspect. The IdP signs real RS256 id_tokens under
 * a key it publishes at `jwksUri`; the knobs below let a test make it
 * misbehave in exactly one way at a time.
 *
 * The same harness as `@o3co/auth-provider-federation-oidc`'s test helper,
 * with the endpoints named explicitly — Google's and Apple's are not paths
 * under the issuer — and no discovery document, since these providers build
 * their metadata locally. Kept identical in the two packages that copy it.
 */
export interface FakeIdpOptions {
	readonly issuer: string;
	readonly tokenEndpoint: string;
	readonly jwksUri: string;
	/** Absent for a provider that publishes none (Apple). */
	readonly userinfoEndpoint?: string;
	readonly clientId?: string;
	readonly sub?: string;
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
	/** Claims laid over the id_token defaults. */
	idTokenClaims: Record<string, unknown>;
	/** The nonce the next id_token echoes; absent when undefined. */
	nonce: string | undefined;
	/** Sign under the current key but claim this `kid` in the header. */
	signingKid: string | undefined;
	/**
	 * Sign under a key that was never published, claiming the published `kid`.
	 * A valid RS256 signature by the wrong key: the case only a signature
	 * check against the JWKS can catch.
	 */
	signWithUnpublishedKey: boolean;
	/** Leave the id_token out of the token response. */
	omitIdToken: boolean;
	/** Claims laid over the userinfo defaults. */
	userinfoClaims: Record<string, unknown>;
	tokenStatus: number;
	accessToken: string;
	/** Replace the signing key; the JWKS then holds only the new one. */
	rotateKey(): Promise<string>;
	currentKid(): string;
	/** Requests to an endpoint, compared on origin and path (a query string is ignored). */
	requestsTo(endpoint: string): RecordedRequest[];
}

function json(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "content-type": "application/json" },
	});
}

const originAndPath = (url: URL): string => `${url.origin}${url.pathname}`;

export async function createFakeIdp(options: FakeIdpOptions): Promise<FakeIdp> {
	const issuer = options.issuer.replace(/\/$/, "");
	const clientId = options.clientId ?? "client-under-test";
	const sub = options.sub ?? "user-0001";
	const endpoints = {
		token: originAndPath(new URL(options.tokenEndpoint)),
		jwks: originAndPath(new URL(options.jwksUri)),
		userinfo:
			options.userinfoEndpoint === undefined
				? undefined
				: originAndPath(new URL(options.userinfoEndpoint)),
	};

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

	const requests: RecordedRequest[] = [];

	const idp: FakeIdp = {
		issuer,
		clientId,
		sub,
		requests,
		idTokenClaims: {},
		nonce: undefined,
		signingKid: undefined,
		signWithUnpublishedKey: false,
		omitIdToken: false,
		userinfoClaims: {},
		tokenStatus: 200,
		accessToken: "at-1",
		fetch: undefined as unknown as typeof fetch,
		rotateKey: newKey,
		currentKid: () => signer.kid,
		requestsTo: (endpoint) => {
			const wanted = originAndPath(new URL(endpoint));
			return requests.filter((r) => originAndPath(r.url) === wanted);
		},
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
			(init?.headers ?? (input instanceof Request ? input.headers : undefined)) as HeadersInit,
		);
		const raw = init?.body;
		const body =
			raw === undefined || raw === null
				? undefined
				: new URLSearchParams(raw instanceof URLSearchParams ? raw : String(raw));
		requests.push({ url, method, headers, body });

		const where = originAndPath(url);
		if (where === endpoints.jwks) return json(jwks);
		if (where === endpoints.token && method === "POST") {
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
