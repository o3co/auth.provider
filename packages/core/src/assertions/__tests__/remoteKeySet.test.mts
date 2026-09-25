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

import { generateKeyPairSync } from "node:crypto";
import { exportJWK, jwtVerify, SignJWT } from "jose";
import { describe, expect, it, vi } from "vitest";
import {
	createRemoteKeySetCache,
	DEFAULT_REMOTE_JWKS_CACHE_MAX_AGE_MS,
	DEFAULT_REMOTE_JWKS_COOLDOWN_MS,
	DEFAULT_REMOTE_JWKS_TIMEOUT_MS,
} from "#/assertions/remoteKeySet.mjs";

/**
 * v0.13.0 audit — the one place a `jwks_uri` becomes a key resolver. There
 * were two (`private_key_jwt` client assertions, #484; the trust-registry
 * assertion verifier, #525), with the same memo and the same tuning, and only
 * one of them took a fetch: a deployment behind an egress proxy could fetch a
 * client's keys but not a trusted issuer's.
 */

const URI = "https://keys.example/jwks.json";
const signer = generateKeyPairSync("ed25519");

const jwksFetch = () =>
	vi.fn(
		async () =>
			new Response(
				JSON.stringify({
					keys: [{ ...(await exportJWK(signer.publicKey)), kid: "k1", alg: "EdDSA" }],
				}),
				{ status: 200, headers: { "content-type": "application/json" } },
			),
	);

const token = () =>
	new SignJWT({ sub: "s" })
		.setProtectedHeader({ alg: "EdDSA", kid: "k1" })
		.setExpirationTime("5m")
		.sign(signer.privateKey);

describe("createRemoteKeySetCache", () => {
	it("fetches through the fetch it is given, once per key set", async () => {
		const fetchImpl = jwksFetch();
		const cache = createRemoteKeySetCache({ fetch: fetchImpl as unknown as typeof fetch });

		await jwtVerify(await token(), cache.keySetFor(URI));
		await jwtVerify(await token(), cache.keySetFor(URI));

		expect(fetchImpl).toHaveBeenCalledTimes(1);
		expect(String(fetchImpl.mock.calls[0]?.[0])).toBe(URI);
	});

	it("hands back one key set per uri and tuning, so a store's fresh entry objects share it", () => {
		const cache = createRemoteKeySetCache();
		expect(cache.keySetFor(URI)).toBe(cache.keySetFor(URI));
		expect(cache.keySetFor(URI, { cooldownMs: 0 })).toBe(cache.keySetFor(URI, { cooldownMs: 0 }));
		// Different tuning is a different key set: the first caller's options do
		// not silently become every later caller's.
		expect(cache.keySetFor(URI, { cooldownMs: 0 })).not.toBe(cache.keySetFor(URI));
		// Defaults spelled out are the defaults.
		expect(
			cache.keySetFor(URI, {
				timeoutMs: DEFAULT_REMOTE_JWKS_TIMEOUT_MS,
				cooldownMs: DEFAULT_REMOTE_JWKS_COOLDOWN_MS,
				cacheMaxAgeMs: DEFAULT_REMOTE_JWKS_CACHE_MAX_AGE_MS,
			}),
		).toBe(cache.keySetFor(URI));
	});

	it("defaults to a 5 s timeout, a 30 s refetch cooldown and a 10 minute cache", () => {
		expect(DEFAULT_REMOTE_JWKS_TIMEOUT_MS).toBe(5_000);
		expect(DEFAULT_REMOTE_JWKS_COOLDOWN_MS).toBe(30_000);
		expect(DEFAULT_REMOTE_JWKS_CACHE_MAX_AGE_MS).toBe(600_000);
	});
});
