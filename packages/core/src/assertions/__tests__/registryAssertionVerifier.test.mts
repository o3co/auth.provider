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

import { generateKeyPairSync, type KeyObject } from "node:crypto";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { exportJWK, SignJWT } from "jose";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import {
	type AssertionIssuerEntry,
	type AssertionIssuerRegistry,
	createMemoryAssertionIssuerRegistry,
} from "#/assertions/issuerRegistry.mjs";
import { createRegistryAssertionVerifier } from "#/assertions/registryAssertionVerifier.mjs";

/**
 * #525 — "we trust these N issuers, each with their own keys and terms", where
 * the one-key verifier was "this key, this issuer". Almost every case is a
 * refusal or an ordering: the value of a registry is what it refuses before
 * doing any work, and what it lets one issuer's terms not leak into another's.
 */

const AS = "https://auth.example";
const ISSUER_A = "https://a.example";
const ISSUER_B = "https://b.example";

const authorityA = generateKeyPairSync("ed25519");
const authorityB = generateKeyPairSync("ed25519");

const mint = async (
	claims: Record<string, unknown>,
	opts: { iss?: string; aud?: string; key?: KeyObject; kid?: string; expSec?: number } = {},
): Promise<string> =>
	new SignJWT(claims)
		.setProtectedHeader({ alg: "EdDSA", ...(opts.kid ? { kid: opts.kid } : {}) })
		.setIssuer(opts.iss ?? ISSUER_A)
		.setAudience(opts.aud ?? AS)
		.setExpirationTime(opts.expSec ?? Math.floor(Date.now() / 1000) + 300)
		.sign(opts.key ?? authorityA.privateKey);

const entryA = (over: Partial<AssertionIssuerEntry> = {}): AssertionIssuerEntry => ({
	issuer: ISSUER_A,
	keys: { type: "key", key: authorityA.publicKey },
	algorithms: ["EdDSA"],
	...over,
});
const entryB = (over: Partial<AssertionIssuerEntry> = {}): AssertionIssuerEntry => ({
	issuer: ISSUER_B,
	keys: { type: "key", key: authorityB.publicKey },
	algorithms: ["EdDSA"],
	...over,
});

const verifierOver = (entries: readonly AssertionIssuerEntry[], audience: string | string[] = AS) =>
	createRegistryAssertionVerifier({
		registry: createMemoryAssertionIssuerRegistry(entries),
		audience,
	});

/** A JWKS endpoint on loopback whose key set can be rotated and whose fetches are counted. */
interface JwksServer {
	readonly uri: string;
	fetches(): number;
	publish(keys: ReadonlyArray<{ kid: string; publicKey: KeyObject }>): Promise<void>;
	fail(status: number | null): void;
	close(): Promise<void>;
}

const startJwksServer = async (): Promise<JwksServer> => {
	let document = JSON.stringify({ keys: [] });
	let fetches = 0;
	let failWith: number | null = null;
	const server: Server = createServer((_req, res) => {
		fetches++;
		if (failWith !== null) {
			res.writeHead(failWith);
			res.end();
			return;
		}
		res.writeHead(200, { "content-type": "application/json" });
		res.end(document);
	});
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	const { port } = server.address() as AddressInfo;
	return {
		uri: `http://127.0.0.1:${port}/jwks`,
		fetches: () => fetches,
		async publish(keys) {
			document = JSON.stringify({
				keys: await Promise.all(
					keys.map(async ({ kid, publicKey }) => ({
						...(await exportJWK(publicKey)),
						kid,
						alg: "EdDSA",
						use: "sig",
					})),
				),
			});
		},
		fail(status) {
			failWith = status;
		},
		close: () => new Promise<void>((resolve) => server.close(() => resolve())),
	};
};

describe("createRegistryAssertionVerifier — issuers and their keys (#525)", () => {
	it("accepts an assertion from a registered issuer and says which issuer it was", async () => {
		const result = await verifierOver([entryA()]).verify(await mint({ sub: "device:1" }));
		expect(result).toEqual({ subjectHandle: "device:1", issuer: ISSUER_A });
	});

	it("keeps two issuers' keys apart", async () => {
		const verifier = verifierOver([entryA(), entryB()]);
		expect(await verifier.verify(await mint({ sub: "d" }))).toMatchObject({ issuer: ISSUER_A });
		expect(
			await verifier.verify(
				await mint({ sub: "d" }, { iss: ISSUER_B, key: authorityB.privateKey }),
			),
		).toMatchObject({ issuer: ISSUER_B });
		// Signed by B, claiming to be A: checked against A's key, refused.
		expect(
			await verifier.verify(
				await mint({ sub: "d" }, { iss: ISSUER_A, key: authorityB.privateKey }),
			),
		).toBeNull();
		expect(
			await verifier.verify(
				await mint({ sub: "d" }, { iss: ISSUER_B, key: authorityA.privateKey }),
			),
		).toBeNull();
	});

	it("refuses an unregistered issuer before any signature work", async () => {
		const findIssuer = vi.fn(async () => null);
		const registry: AssertionIssuerRegistry = { kind: "spy", findIssuer };
		const verifier = createRegistryAssertionVerifier({ registry, audience: AS });
		expect(
			await verifier.verify(await mint({ sub: "d" }, { iss: "https://nobody.example" })),
		).toBeNull();
		expect(findIssuer).toHaveBeenCalledWith("https://nobody.example");
	});

	it("refuses an assertion with no iss, and a string that is not a JWT, without consulting the registry", async () => {
		const findIssuer = vi.fn(async () => entryA());
		const verifier = createRegistryAssertionVerifier({
			registry: { kind: "spy", findIssuer },
			audience: AS,
		});
		const noIss = await new SignJWT({ sub: "d" })
			.setProtectedHeader({ alg: "EdDSA" })
			.setAudience(AS)
			.setExpirationTime("5m")
			.sign(authorityA.privateKey);
		expect(await verifier.verify(noIss)).toBeNull();
		expect(await verifier.verify("device-1234")).toBeNull();
		expect(await verifier.verify("")).toBeNull();
		expect(findIssuer).not.toHaveBeenCalled();
	});

	it("lets a registry outage propagate — it is not a refusal", async () => {
		const verifier = createRegistryAssertionVerifier({
			registry: {
				kind: "down",
				findIssuer: async () => {
					throw new Error("registry store unreachable");
				},
			},
			audience: AS,
		});
		await expect(verifier.verify(await mint({ sub: "d" }))).rejects.toThrow(/unreachable/);
	});

	it("takes a static JWK set and selects the key by kid", async () => {
		const verifier = verifierOver([
			entryA({
				keys: {
					type: "jwks",
					jwks: {
						keys: [
							{ ...(await exportJWK(authorityB.publicKey)), kid: "old", alg: "EdDSA" },
							{ ...(await exportJWK(authorityA.publicKey)), kid: "k1", alg: "EdDSA" },
						],
					},
				},
			}),
		]);
		expect(await verifier.verify(await mint({ sub: "d" }, { kid: "k1" }))).toMatchObject({
			subjectHandle: "d",
		});
		expect(await verifier.verify(await mint({ sub: "d" }, { kid: "unknown" }))).toBeNull();
	});
});

describe("createRegistryAssertionVerifier — a remote JWKS endpoint (#525)", () => {
	let jwks: JwksServer;
	const rotated = generateKeyPairSync("ed25519");

	beforeAll(async () => {
		jwks = await startJwksServer();
		await jwks.publish([{ kid: "k1", publicKey: authorityA.publicKey }]);
	});
	afterAll(async () => {
		await jwks.close();
	});

	const remoteEntry = (): AssertionIssuerEntry =>
		entryA({ keys: { type: "jwks_uri", uri: jwks.uri, cooldownMs: 0, cacheMaxAgeMs: 60_000 } });

	it("fetches the key set on first use, and a rotation at the issuer is picked up without a restart", async () => {
		const verifier = verifierOver([remoteEntry()]);
		const before = jwks.fetches();
		expect(await verifier.verify(await mint({ sub: "d" }, { kid: "k1" }))).toMatchObject({
			subjectHandle: "d",
		});
		expect(jwks.fetches()).toBe(before + 1);
		// Cached: a second assertion under the same kid costs no fetch.
		expect(await verifier.verify(await mint({ sub: "d" }, { kid: "k1" }))).not.toBeNull();
		expect(jwks.fetches()).toBe(before + 1);

		// The issuer rotates. An unknown kid triggers exactly one refetch, and
		// the old key is gone with it.
		await jwks.publish([{ kid: "k2", publicKey: rotated.publicKey }]);
		expect(
			await verifier.verify(await mint({ sub: "d" }, { kid: "k2", key: rotated.privateKey })),
		).toMatchObject({ subjectHandle: "d" });
		expect(jwks.fetches()).toBe(before + 2);
		expect(await verifier.verify(await mint({ sub: "d" }, { kid: "k1" }))).toBeNull();
	});

	it("does not fetch for an issuer that is not registered", async () => {
		const verifier = verifierOver([remoteEntry()]);
		const before = jwks.fetches();
		expect(
			await verifier.verify(
				await mint({ sub: "d" }, { iss: ISSUER_B, key: authorityB.privateKey }),
			),
		).toBeNull();
		expect(jwks.fetches()).toBe(before);
	});

	it("throws, rather than refusing, when the endpoint is down — the grant answers 503", async () => {
		// A device whose issuer's JWKS endpoint is unreachable has not presented
		// a bad credential; telling it so would send an operator to re-enrol a
		// device that was fine (the #408 distinction).
		const verifier = verifierOver([
			entryA({ keys: { type: "jwks_uri", uri: jwks.uri, cooldownMs: 0, cacheMaxAgeMs: 0 } }),
		]);
		jwks.fail(503);
		try {
			await expect(
				verifier.verify(await mint({ sub: "d" }, { kid: "k2", key: rotated.privateKey })),
			).rejects.toThrow();
		} finally {
			jwks.fail(null);
		}
	});
});

describe("createRegistryAssertionVerifier — the terms of an entry (#525)", () => {
	it("admits only the clients an entry names, and no unauthenticated presenter when it names any", async () => {
		const verifier = verifierOver([entryA({ allowedClients: ["mobile-app"] })]);
		const assertion = await mint({ sub: "d" });
		expect(await verifier.verify(assertion, { clientId: "mobile-app" })).not.toBeNull();
		expect(await verifier.verify(assertion, { clientId: "other-app" })).toBeNull();
		expect(await verifier.verify(assertion, {})).toBeNull();
		expect(await verifier.verify(assertion)).toBeNull();
	});

	it("admits any presenter, an unauthenticated one included, when the entry names no clients", async () => {
		const verifier = verifierOver([entryA()]);
		const assertion = await mint({ sub: "d" });
		expect(await verifier.verify(assertion, { clientId: "anyone" })).not.toBeNull();
		expect(await verifier.verify(assertion)).not.toBeNull();
	});

	it("refuses an expired entry, and accepts it again once the expiry is lifted", async () => {
		const registry = createMemoryAssertionIssuerRegistry([
			entryA({ expiresAt: new Date(Date.now() - 1) }),
		]);
		const verifier = createRegistryAssertionVerifier({ registry, audience: AS });
		const assertion = await mint({ sub: "d" });
		expect(await verifier.verify(assertion)).toBeNull();
		await registry.setExpiresAt(ISSUER_A, new Date(Date.now() + 60_000));
		expect(await verifier.verify(assertion)).not.toBeNull();
	});

	it("admits only the subjects an entry names", async () => {
		const verifier = verifierOver([entryA({ allowedSubjects: ["device:1"] })]);
		expect(await verifier.verify(await mint({ sub: "device:1" }))).not.toBeNull();
		expect(await verifier.verify(await mint({ sub: "device:2" }))).toBeNull();
	});

	it("intersects the scope claim with allowedScopes, and takes allowedScopes alone when the assertion names none", async () => {
		const verifier = verifierOver([entryA({ allowedScopes: ["read", "write"] })]);
		expect((await verifier.verify(await mint({ sub: "d", scope: "read admin" })))?.scope).toEqual([
			"read",
		]);
		expect((await verifier.verify(await mint({ sub: "d" })))?.scope).toEqual(["read", "write"]);
		// No entry ceiling: the claim alone, or nothing.
		const open = verifierOver([entryA()]);
		expect((await open.verify(await mint({ sub: "d", scope: "read admin" })))?.scope).toEqual([
			"read",
			"admin",
		]);
		expect((await open.verify(await mint({ sub: "d" })))?.scope).toBeUndefined();
	});

	it("carries allowedAudiences through as the audience ceiling", async () => {
		const verifier = verifierOver([entryA({ allowedAudiences: ["https://api.example"] })]);
		expect((await verifier.verify(await mint({ sub: "d" })))?.audience).toEqual([
			"https://api.example",
		]);
		expect(
			(await verifierOver([entryA()]).verify(await mint({ sub: "d" })))?.audience,
		).toBeUndefined();
	});

	it("honours a custom handle reader per entry", async () => {
		const verifier = verifierOver([
			entryA({
				readSubjectHandle: (c) =>
					typeof c.device_id === "string" ? `device:${c.device_id}` : null,
			}),
		]);
		expect((await verifier.verify(await mint({ device_id: "abc" })))?.subjectHandle).toBe(
			"device:abc",
		);
	});
});

describe("createRegistryAssertionVerifier — what every entry refuses (#525)", () => {
	it("refuses an assertion not addressed to this server, and accepts any of several names for it", async () => {
		const verifier = verifierOver([entryA()], [AS, `${AS}/oauth/token`]);
		expect(await verifier.verify(await mint({ sub: "d" }, { aud: AS }))).not.toBeNull();
		expect(
			await verifier.verify(await mint({ sub: "d" }, { aud: `${AS}/oauth/token` })),
		).not.toBeNull();
		expect(
			await verifier.verify(await mint({ sub: "d" }, { aud: "https://elsewhere.example" })),
		).toBeNull();
	});

	it("refuses an expired assertion, one with no exp, and an algorithm off the list", async () => {
		const verifier = verifierOver([entryA()]);
		expect(
			await verifier.verify(
				await mint({ sub: "d" }, { expSec: Math.floor(Date.now() / 1000) - 3600 }),
			),
		).toBeNull();
		const noExp = await new SignJWT({ sub: "d" })
			.setProtectedHeader({ alg: "EdDSA" })
			.setIssuer(ISSUER_A)
			.setAudience(AS)
			.sign(authorityA.privateKey);
		expect(await verifier.verify(noExp)).toBeNull();
		const hs = await new SignJWT({ sub: "d" })
			.setProtectedHeader({ alg: "HS256" })
			.setIssuer(ISSUER_A)
			.setAudience(AS)
			.setExpirationTime("5m")
			.sign(new TextEncoder().encode("a-shared-secret-at-least-32-bytes!!"));
		expect(await verifier.verify(hs)).toBeNull();
	});

	it("refuses a verified assertion that names nobody", async () => {
		expect(await verifierOver([entryA()]).verify(await mint({}))).toBeNull();
		expect(await verifierOver([entryA()]).verify(await mint({ sub: "" }))).toBeNull();
	});

	it("requires an audience to build, and reports its kind", () => {
		expect(() => verifierOver([entryA()], [])).toThrow(/audience is required/);
		expect(() => verifierOver([entryA()], "")).toThrow(/audience is required/);
		expect(verifierOver([entryA()]).kind).toBe("jwt-registry");
		expect(
			createRegistryAssertionVerifier({
				registry: createMemoryAssertionIssuerRegistry(),
				audience: AS,
				kind: "custom",
			}).kind,
		).toBe("custom");
	});
});
