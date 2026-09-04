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

import { decodeProtectedHeader, jwtVerify } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import type { AppleClientSecretOptions } from "#/client-secret.mjs";
import {
	APPLE_AUDIENCE,
	APPLE_CLIENT_SECRET_DEFAULT_LIFETIME_SECONDS,
	APPLE_CLIENT_SECRET_MAX_LIFETIME_SECONDS,
	APPLE_CLIENT_SECRET_RENEWAL_WINDOW_SECONDS,
	createAppleClientSecret,
} from "#/client-secret.mjs";
import { makeTestSigningKey, type TestSigningKey } from "./helpers.mjs";

const TEAM_ID = "ABCDE12345";
const CLIENT_ID = "com.example.app.service";
const KEY_ID = "XYZW98765F";

let key: TestSigningKey;

beforeAll(async () => {
	key = await makeTestSigningKey();
});

const baseOptions = () => ({
	teamId: TEAM_ID,
	clientId: CLIENT_ID,
	keyId: KEY_ID,
	privateKey: key.privateKeyPem,
});

describe("createAppleClientSecret — the JWT Apple documents", () => {
	it("signs ES256 and names the key in the header `kid`", async () => {
		const jwt = await createAppleClientSecret(baseOptions())();
		const header = decodeProtectedHeader(jwt);
		expect(header.alg).toBe("ES256");
		expect(header.kid).toBe(KEY_ID);
	});

	it("carries iss = Team ID, sub = Services ID, aud = appleid.apple.com, and iat/exp", async () => {
		const now = 1_800_000_000_000;
		const jwt = await createAppleClientSecret({ ...baseOptions(), now: () => now })();
		const { payload } = await jwtVerify(jwt, key.publicKey, {
			issuer: TEAM_ID,
			audience: APPLE_AUDIENCE,
		});
		expect(payload.iss).toBe(TEAM_ID);
		expect(payload.sub).toBe(CLIENT_ID);
		expect(payload.aud).toBe(APPLE_AUDIENCE);
		expect(payload.iat).toBe(Math.floor(now / 1000));
		expect(payload.exp).toBe(Math.floor(now / 1000) + APPLE_CLIENT_SECRET_DEFAULT_LIFETIME_SECONDS);
	});

	it("verifies against the public half of the .p8 key", async () => {
		const jwt = await createAppleClientSecret(baseOptions())();
		await expect(jwtVerify(jwt, key.publicKey)).resolves.toBeDefined();
	});

	it("keeps exp inside Apple's six-month ceiling by default", async () => {
		expect(APPLE_CLIENT_SECRET_MAX_LIFETIME_SECONDS).toBe(15_777_000);
		expect(APPLE_CLIENT_SECRET_DEFAULT_LIFETIME_SECONDS).toBeLessThanOrEqual(
			APPLE_CLIENT_SECRET_MAX_LIFETIME_SECONDS,
		);
	});

	it("honours a shorter configured lifetime", async () => {
		const now = 1_800_000_000_000;
		const jwt = await createAppleClientSecret({
			...baseOptions(),
			lifetimeSeconds: 3600,
			now: () => now,
		})();
		const { payload } = await jwtVerify(jwt, key.publicKey);
		expect(payload.exp).toBe(Math.floor(now / 1000) + 3600);
	});

	it("refuses a lifetime beyond the six-month ceiling rather than letting Apple reject it", () => {
		expect(() =>
			createAppleClientSecret({
				...baseOptions(),
				lifetimeSeconds: APPLE_CLIENT_SECRET_MAX_LIFETIME_SECONDS + 1,
			}),
		).toThrow(/six months|15777000|lifetime/i);
	});

	it("refuses a non-positive lifetime", () => {
		expect(() => createAppleClientSecret({ ...baseOptions(), lifetimeSeconds: 0 })).toThrow(
			/lifetime/i,
		);
	});

	it.each(["teamId", "clientId", "keyId", "privateKey"] as const)(
		"refuses to build without %s",
		(field) => {
			expect(() => createAppleClientSecret({ ...baseOptions(), [field]: "" })).toThrow(
				new RegExp(field, "i"),
			);
		},
	);

	it("surfaces an unusable .p8 as an error from the resolver, not a malformed secret", async () => {
		const resolve = createAppleClientSecret({
			...baseOptions(),
			privateKey: "-----BEGIN PRIVATE KEY-----\nnot-a-key\n-----END PRIVATE KEY-----\n",
		});
		await expect(resolve()).rejects.toThrow();
	});
});

describe("createAppleClientSecret — caching and rotation", () => {
	it("reuses the signed JWT instead of re-signing per token exchange", async () => {
		const resolve = createAppleClientSecret(baseOptions());
		const first = await resolve();
		const second = await resolve();
		expect(second).toBe(first);
	});

	it("regenerates once the cached secret is inside the 24 h renewal window", async () => {
		expect(APPLE_CLIENT_SECRET_RENEWAL_WINDOW_SECONDS).toBe(86_400);

		let nowMs = 1_800_000_000_000;
		const resolve = createAppleClientSecret({
			...baseOptions(),
			lifetimeSeconds: 7 * 24 * 3600,
			now: () => nowMs,
		});
		const first = await resolve();

		// One second before the window opens: still the cached secret.
		nowMs += (7 * 24 * 3600 - APPLE_CLIENT_SECRET_RENEWAL_WINDOW_SECONDS - 1) * 1000;
		expect(await resolve()).toBe(first);

		// Inside the window: a fresh JWT, with a later exp.
		nowMs += 2000;
		const renewed = await resolve();
		expect(renewed).not.toBe(first);
		const { payload } = await jwtVerify(renewed, key.publicKey);
		expect(payload.iat).toBe(Math.floor(nowMs / 1000));
	});

	it("regenerates an already-expired secret", async () => {
		let nowMs = 1_800_000_000_000;
		const resolve = createAppleClientSecret({
			...baseOptions(),
			lifetimeSeconds: 3600,
			now: () => nowMs,
		});
		const first = await resolve();
		nowMs += 2 * 3600 * 1000;
		expect(await resolve()).not.toBe(first);
	});

	it("signs once for concurrent callers rather than once per caller", async () => {
		const resolve = createAppleClientSecret(baseOptions());
		const [a, b, c] = await Promise.all([resolve(), resolve(), resolve()]);
		expect(b).toBe(a);
		expect(c).toBe(a);
	});

	it("does not poison the cache when signing fails — a later call retries", async () => {
		// The key material is read at signing time, not memoised at construction:
		// a deployment whose mounted `.p8` is repaired or rotated under it must
		// not be stuck on the first failure until someone restarts the process.
		let privateKey = "-----BEGIN PRIVATE KEY-----\nbroken\n-----END PRIVATE KEY-----\n";
		const options: AppleClientSecretOptions = {
			teamId: TEAM_ID,
			clientId: CLIENT_ID,
			keyId: KEY_ID,
			get privateKey() {
				return privateKey;
			},
		};
		const resolve = createAppleClientSecret(options);
		await expect(resolve()).rejects.toThrow();
		privateKey = key.privateKeyPem;
		await expect(resolve()).resolves.toMatch(/^[\w-]+\.[\w-]+\.[\w-]+$/);
	});
});
