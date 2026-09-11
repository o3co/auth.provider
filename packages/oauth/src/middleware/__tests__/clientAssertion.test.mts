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

import { randomUUID } from "node:crypto";
import {
	createMemoryReplaySeenSet,
	type Logger,
	type PublicClient,
	type ReplaySeenSet,
} from "@o3co/auth-provider-core";
import { exportJWK, generateKeyPair, type JWK, SignJWT } from "jose";
import { beforeAll, describe, expect, it, vi } from "vitest";
import {
	CLIENT_ASSERTION_ALGORITHMS,
	createClientAssertionVerifier,
	JWT_BEARER_CLIENT_ASSERTION_TYPE,
	MAX_CLIENT_ASSERTION_LIFETIME_SECONDS,
} from "#/middleware/clientAssertion.mjs";

/**
 * #484 — `private_key_jwt` client authentication (RFC 7523 §2.2, OIDC Core §9).
 *
 * The verifier is the whole of the trust decision: which client the assertion
 * names, whose keys it must verify under, what the claims must say, and that
 * the `jti` is spent exactly once. The middleware around it only decides how
 * to answer.
 */
const ISSUER = "https://auth.test";
const TOKEN_ENDPOINT = "https://auth.test/oauth/token";
const CLIENT_ID = "rp-1";

const silent: Logger = {
	debug: () => {},
	info: () => {},
	warn: () => {},
	error: () => {},
	fatal: () => {},
	child: () => silent,
};

type Pair = { privateKey: CryptoKey; publicJwk: JWK };
let rp: Pair;
let stranger: Pair;

beforeAll(async () => {
	const a = await generateKeyPair("ES256");
	const b = await generateKeyPair("ES256");
	rp = { privateKey: a.privateKey, publicJwk: { ...(await exportJWK(a.publicKey)), kid: "k1" } };
	stranger = {
		privateKey: b.privateKey,
		publicJwk: { ...(await exportJWK(b.publicKey)), kid: "k2" },
	};
});

const client = (overrides: Partial<PublicClient> = {}): PublicClient => ({
	clientId: CLIENT_ID,
	tokenEndpointAuthMethod: "private_key_jwt",
	allowedRedirectUris: [],
	allowedScopes: [],
	jwks: { keys: [rp.publicJwk] },
	...overrides,
});

const findClient = (c: PublicClient | null = client()) =>
	vi.fn(async (id: string) => (c !== null && id === c.clientId ? c : null));

async function mint(
	claims: Record<string, unknown> = {},
	opts: { key?: CryptoKey | Uint8Array; kid?: string; alg?: string } = {},
): Promise<string> {
	const now = Math.floor(Date.now() / 1000);
	const payload = {
		iss: CLIENT_ID,
		sub: CLIENT_ID,
		aud: TOKEN_ENDPOINT,
		iat: now,
		exp: now + 60,
		jti: randomUUID(),
		...claims,
	};
	return new SignJWT(payload)
		.setProtectedHeader({ alg: opts.alg ?? "ES256", kid: opts.kid ?? "k1" })
		.sign(opts.key ?? rp.privateKey);
}

const body = (assertion: string, extra: Record<string, unknown> = {}) => ({
	client_assertion_type: JWT_BEARER_CLIENT_ASSERTION_TYPE,
	client_assertion: assertion,
	...extra,
});

const build = (overrides: Partial<Parameters<typeof createClientAssertionVerifier>[0]> = {}) =>
	createClientAssertionVerifier({
		issuer: ISSUER,
		tokenEndpoint: TOKEN_ENDPOINT,
		replaySeenSet: createMemoryReplaySeenSet(),
		logger: silent,
		...overrides,
	});

const refused = (outcome: unknown) => {
	expect(outcome).toMatchObject({ kind: "refused" });
	return outcome as { status: number; error: string; description?: string };
};

describe("createClientAssertionVerifier (#484)", () => {
	describe("presence and shape", () => {
		it("reports an absent assertion, leaving the other methods to the middleware", async () => {
			expect(await build().verify({}, findClient())).toEqual({ kind: "absent" });
			expect(await build().verify(undefined, findClient())).toEqual({ kind: "absent" });
			expect(await build().verify({ client_id: CLIENT_ID }, findClient())).toEqual({
				kind: "absent",
			});
		});

		it("refuses half a pair as a malformed request", async () => {
			const one = refused(await build().verify({ client_assertion: await mint() }, findClient()));
			expect(one).toMatchObject({ status: 400, error: "invalid_request" });
			const other = refused(
				await build().verify(
					{ client_assertion_type: JWT_BEARER_CLIENT_ASSERTION_TYPE },
					findClient(),
				),
			);
			expect(other).toMatchObject({ status: 400, error: "invalid_request" });
		});

		it("refuses any assertion type but jwt-bearer", async () => {
			const out = refused(
				await build().verify(
					{
						client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:saml2-bearer",
						client_assertion: await mint(),
					},
					findClient(),
				),
			);
			expect(out).toMatchObject({ status: 401, error: "invalid_client" });
			expect(out.description).toMatch(/client_assertion_type/);
		});

		it("refuses something that is not a JWT", async () => {
			expect(refused(await build().verify(body("not.a.jwt"), findClient()))).toMatchObject({
				status: 401,
				error: "invalid_client",
			});
		});
	});

	describe("who the assertion names", () => {
		it("accepts iss = sub = client_id, looks the client up by it, and returns the registration", async () => {
			const find = findClient();
			const out = await build().verify(body(await mint()), find);
			expect(out).toMatchObject({ kind: "ok", client: { clientId: CLIENT_ID } });
			expect(find).toHaveBeenCalledWith(CLIENT_ID);
		});

		it("refuses iss ≠ sub, and a body client_id that disagrees", async () => {
			const a = refused(
				await build().verify(body(await mint({ sub: "someone-else" })), findClient()),
			);
			expect(a.description).toMatch(/iss and sub/);
			const b = refused(
				await build().verify(body(await mint(), { client_id: "someone-else" }), findClient()),
			);
			expect(b.description).toMatch(/client_id/);
			// A body client_id that agrees is fine (RFC 7523 §2.2: it MAY be present).
			expect(
				await build().verify(body(await mint(), { client_id: CLIENT_ID }), findClient()),
			).toMatchObject({
				kind: "ok",
			});
		});

		it("refuses an unknown client, and fails closed when the lookup throws", async () => {
			expect(refused(await build().verify(body(await mint()), findClient(null)))).toMatchObject({
				status: 401,
				error: "invalid_client",
			});
			const throwing = vi.fn(async () => {
				throw new Error("store down");
			});
			expect(refused(await build().verify(body(await mint()), throwing))).toMatchObject({
				status: 401,
				error: "invalid_client",
			});
		});

		it("refuses a client registered for another method, in the middleware's words", async () => {
			const out = refused(
				await build().verify(
					body(await mint()),
					findClient(client({ tokenEndpointAuthMethod: "client_secret_basic", jwks: undefined })),
				),
			);
			expect(out.description).toMatch(/tokenEndpointAuthMethod mismatch.*client_secret_basic/);
		});
	});

	describe("signature and keys", () => {
		it("refuses a signature under a key the registration does not hold", async () => {
			const out = refused(
				await build().verify(
					body(await mint({}, { key: stranger.privateKey, kid: "k1" })),
					findClient(),
				),
			);
			expect(out).toMatchObject({ status: 401, error: "invalid_client" });
		});

		it("refuses a kid the JWKS does not publish", async () => {
			expect(
				refused(await build().verify(body(await mint({}, { kid: "k-ghost" })), findClient())),
			).toMatchObject({ status: 401 });
		});

		it("refuses symmetric and none algorithms outright", async () => {
			expect(CLIENT_ASSERTION_ALGORITHMS).not.toContain("HS256");
			expect(CLIENT_ASSERTION_ALGORITHMS).not.toContain("none");
			const hmac = await mint({}, { key: new TextEncoder().encode("x".repeat(32)), alg: "HS256" });
			expect(refused(await build().verify(body(hmac), findClient()))).toMatchObject({
				status: 401,
			});

			const header = Buffer.from(JSON.stringify({ alg: "none" })).toString("base64url");
			const payload = Buffer.from(
				JSON.stringify({ iss: CLIENT_ID, sub: CLIENT_ID, aud: TOKEN_ENDPOINT, exp: 9e9, jti: "j" }),
			).toString("base64url");
			expect(
				refused(await build().verify(body(`${header}.${payload}.`), findClient())),
			).toMatchObject({
				status: 401,
			});
		});

		it("answers server_error for a private_key_jwt registration that carries no keys", async () => {
			const out = refused(
				await build().verify(body(await mint()), findClient(client({ jwks: undefined }))),
			);
			expect(out).toMatchObject({ status: 500, error: "server_error" });
		});

		it("fetches jwks_uri once, caches it, and refuses what it does not hold", async () => {
			const fetchImpl = vi.fn(
				async () =>
					new Response(JSON.stringify({ keys: [rp.publicJwk] }), {
						status: 200,
						headers: { "content-type": "application/json" },
					}),
			);
			const remote = client({ jwks: undefined, jwksUri: "https://rp.test/jwks.json" });
			const verifier = build({ fetch: fetchImpl as unknown as typeof fetch });
			expect(await verifier.verify(body(await mint()), findClient(remote))).toMatchObject({
				kind: "ok",
			});
			expect(await verifier.verify(body(await mint()), findClient(remote))).toMatchObject({
				kind: "ok",
			});
			expect(fetchImpl).toHaveBeenCalledTimes(1);
			expect(String(fetchImpl.mock.calls[0]?.[0])).toBe("https://rp.test/jwks.json");
			expect(
				refused(
					await verifier.verify(
						body(await mint({}, { key: stranger.privateKey, kid: "k2" })),
						findClient(remote),
					),
				),
			).toMatchObject({ status: 401 });
		});

		it("fails closed when jwks_uri cannot be fetched", async () => {
			const fetchImpl = vi.fn(async () => {
				throw new Error("ECONNREFUSED");
			});
			const remote = client({ jwks: undefined, jwksUri: "https://rp.test/jwks.json" });
			const out = refused(
				await build({ fetch: fetchImpl as unknown as typeof fetch }).verify(
					body(await mint()),
					findClient(remote),
				),
			);
			expect(out).toMatchObject({ status: 401, error: "invalid_client" });
		});
	});

	describe("claims", () => {
		it("accepts aud = token endpoint and aud = issuer, and refuses anything else", async () => {
			expect(
				await build().verify(body(await mint({ aud: TOKEN_ENDPOINT })), findClient()),
			).toMatchObject({ kind: "ok" });
			expect(await build().verify(body(await mint({ aud: ISSUER })), findClient())).toMatchObject({
				kind: "ok",
			});
			expect(
				await build().verify(
					body(await mint({ aud: [ISSUER, "https://other.test"] })),
					findClient(),
				),
			).toMatchObject({
				kind: "ok",
			});
			expect(
				refused(
					await build().verify(
						body(await mint({ aud: "https://other.test/oauth/token" })),
						findClient(),
					),
				),
			).toMatchObject({ status: 401 });
			expect(
				refused(await build().verify(body(await mint({ aud: undefined })), findClient())),
			).toMatchObject({ status: 401 });
		});

		it("refuses an expired assertion, one without exp, and one that lives too long", async () => {
			const now = Math.floor(Date.now() / 1000);
			expect(
				refused(await build().verify(body(await mint({ exp: now - 120 })), findClient())),
			).toMatchObject({ status: 401 });
			expect(
				refused(await build().verify(body(await mint({ exp: undefined })), findClient())),
			).toMatchObject({ status: 401 });
			const tooLong = refused(
				await build().verify(
					body(await mint({ exp: now + MAX_CLIENT_ASSERTION_LIFETIME_SECONDS + 120 })),
					findClient(),
				),
			);
			expect(tooLong.description).toMatch(/exp/);
			expect(
				await build().verify(
					body(await mint({ exp: now + MAX_CLIENT_ASSERTION_LIFETIME_SECONDS - 5 })),
					findClient(),
				),
			).toMatchObject({ kind: "ok" });
		});

		it("bounds iat when present: not ahead of the clock beyond tolerance, not older than the lifetime ceiling", async () => {
			const now = Math.floor(Date.now() / 1000);
			const future = refused(
				await build().verify(body(await mint({ iat: now + 120 })), findClient()),
			);
			expect(future).toMatchObject({ status: 401 });
			expect(future.description).toMatch(/iat/);
			const stale = refused(
				await build().verify(
					body(await mint({ iat: now - MAX_CLIENT_ASSERTION_LIFETIME_SECONDS - 120 })),
					findClient(),
				),
			);
			expect(stale.description).toMatch(/iat/);
			// Inside the tolerance either way, and RFC 7523 §3 makes iat optional.
			expect(await build().verify(body(await mint({ iat: now + 20 })), findClient())).toMatchObject(
				{ kind: "ok" },
			);
			expect(
				await build().verify(
					body(await mint({ iat: now - MAX_CLIENT_ASSERTION_LIFETIME_SECONDS - 20 })),
					findClient(),
				),
			).toMatchObject({ kind: "ok" });
			expect(
				await build().verify(body(await mint({ iat: undefined })), findClient()),
			).toMatchObject({ kind: "ok" });
		});

		it("requires a jti and spends it: the same assertion is refused the second time", async () => {
			expect(
				refused(await build().verify(body(await mint({ jti: undefined })), findClient())),
			).toMatchObject({ status: 401 });
			const verifier = build();
			const assertion = await mint();
			expect(await verifier.verify(body(assertion), findClient())).toMatchObject({ kind: "ok" });
			const replay = refused(await verifier.verify(body(assertion), findClient()));
			expect(replay).toMatchObject({ status: 401, error: "invalid_client" });
			expect(replay.description).toMatch(/jti/);
			// A fresh jti under the same key is a new authentication.
			expect(await verifier.verify(body(await mint()), findClient())).toMatchObject({ kind: "ok" });
		});

		it("scopes the jti record to the client, and keeps it until the assertion expires", async () => {
			const store = createMemoryReplaySeenSet();
			const markSeen = vi.spyOn(store, "markSeen");
			const now = Math.floor(Date.now() / 1000);
			await build({ replaySeenSet: store }).verify(
				body(await mint({ jti: "j-1", exp: now + 60 })),
				findClient(),
			);
			expect(markSeen).toHaveBeenCalledTimes(1);
			const [scope, key, expiresAtMs] = markSeen.mock.calls[0] as [string, string, number];
			expect(scope).toBe(`client-assertion:${CLIENT_ID}`);
			expect(key).toBe("j-1");
			expect(expiresAtMs).toBeGreaterThanOrEqual((now + 60) * 1000);
		});

		it("answers server_error without a replay store, and temporarily_unavailable when it fails", async () => {
			const none = refused(
				await build({ replaySeenSet: undefined }).verify(body(await mint()), findClient()),
			);
			expect(none).toMatchObject({ status: 500, error: "server_error" });
			expect(none.description).toMatch(/replaySeenSet/);

			const broken: ReplaySeenSet = {
				kind: "broken",
				markSeen: async () => {
					throw new Error("redis down");
				},
				contains: async () => false,
			};
			expect(
				refused(await build({ replaySeenSet: broken }).verify(body(await mint()), findClient())),
			).toMatchObject({
				status: 503,
				error: "temporarily_unavailable",
			});
		});
	});
});
