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

/**
 * A keystore refuses, when it is built, a `kid` that `verifyJwt` would refuse.
 *
 * `verifyJwt` refuses a `kid` header that is not a well-formed key id — not a
 * string, empty, longer than `MAX_KID_LENGTH`, or carrying a control
 * character — as `kid_unknown`, before any keystore is asked. A keystore
 * configured with such a kid built and signed without complaint, and then
 * every token it signed was refused: a total outage, reported as the
 * client's fault. So the rule is checked where the kid is chosen — the
 * current kid, every previous kid, on the local stores and the remote-signing
 * one, and in `oauth.jwt.signingKey` — and a kid that passes is one the
 * verifier asks for.
 */

import { generateKeyPairSync, sign as nodeSign } from "node:crypto";
import { describe, expect, it } from "vitest";
import { CoreConfigSchema } from "#/config/application.schema.mjs";
import { verifyJwt } from "#/jwt/verify.mjs";
import { createAsymmetricKeyStore, createSymmetricKeyStore } from "#/keys/KeyStore.mjs";
import { MAX_KID_LENGTH } from "#/keys/kid.mjs";
import { createRemoteSigningKeyStore } from "#/keys/remoteSigning.mjs";

const SECRET = "x".repeat(64);
const ISSUER = "https://as.example";
const ed = generateKeyPairSync("ed25519");
const publicKeyPem = ed.publicKey.export({ type: "spki", format: "pem" }).toString();
const privateKeyPem = ed.privateKey.export({ type: "pkcs8", format: "pem" }).toString();
const signer = {
	sign: async (_kid: string, data: Uint8Array) =>
		new Uint8Array(nodeSign(null, data, ed.privateKey)),
};
const future = new Date(Date.now() + 600_000);

const MALFORMED: ReadonlyArray<readonly [string, unknown]> = [
	["longer than MAX_KID_LENGTH", "k".repeat(MAX_KID_LENGTH + 1)],
	["empty", ""],
	["carrying a line feed", "v1\nv2"],
	["carrying a NUL byte", "v1\u0000"],
	["a C1 control character", "v1\u0085"],
	["not a string", 7],
];

const symmetric = (kid: unknown, previousKid = "old") =>
	createSymmetricKeyStore(SECRET, kid as string, [
		{ kid: previousKid, secret: "y".repeat(64), expiresAt: future },
	]);
const asymmetric = (kid: unknown, previousKid: unknown = "old") =>
	createAsymmetricKeyStore({
		algorithm: "EdDSA",
		kid: kid as string,
		privateKeyPem,
		publicKeyPem,
		previousKeys: [{ kid: previousKid as string, publicKeyPem, expiresAt: future }],
	});
const remote = (kid: unknown, previousKid: unknown = "old") =>
	createRemoteSigningKeyStore({
		algorithm: "EdDSA",
		kid: kid as string,
		signer,
		publicKeyPem,
		previousKeys: [{ kid: previousKid as string, publicKeyPem, expiresAt: future }],
	});

describe("a keystore refuses, when built, a kid verifyJwt would refuse", () => {
	for (const [label, kid] of MALFORMED) {
		describe(label, () => {
			it("as the symmetric store's current kid and as a previous kid", () => {
				expect(() => symmetric(kid)).toThrow(/kid/);
				expect(() => symmetric("v0", kid as string)).toThrow(/previousSecrets\[0\]\.kid/);
			});

			it("as the asymmetric store's current kid and as a previous kid", async () => {
				await expect(asymmetric(kid)).rejects.toThrow(/kid/);
				await expect(asymmetric("v0", kid)).rejects.toThrow(/previousKeys\[0\]\.kid/);
			});

			it("as the remote-signing store's current kid and as a previous kid", async () => {
				await expect(remote(kid)).rejects.toThrow(/kid/);
				await expect(remote("v0", kid)).rejects.toThrow(/previousKeys\[0\]\.kid/);
			});

			it("in oauth.jwt.signingKey — the current kid, previousSecrets and previousKeys", () => {
				const jwt = CoreConfigSchema.shape.oauth.shape.jwt;
				const parse = (local: Record<string, unknown>) =>
					jwt.safeParse({ issuer: ISSUER, signingKey: { provider: "local", local } });
				const hs = { algorithm: "HS256", kid: "v0", secret: SECRET, previousSecrets: [] };
				const ed25519 = { algorithm: "EdDSA", kid: "v0", privateKey: "p", publicKey: "q" };
				expect(parse({ ...hs, kid }).success).toBe(false);
				expect(
					parse({
						...hs,
						previousSecrets: [{ kid, secret: SECRET, expiresAt: "2030-01-01T00:00:00Z" }],
					}).success,
				).toBe(false);
				expect(parse({ ...ed25519, kid }).success).toBe(false);
				expect(
					parse({
						...ed25519,
						previousKeys: [{ kid, publicKey: "q", expiresAt: "2030-01-01T00:00:00Z" }],
					}).success,
				).toBe(false);
			});
		});
	}

	it("never repeats a kid carrying a control character in its message", () => {
		expect(() => symmetric("v1\u001b[31m")).toThrow(
			expect.objectContaining({ message: expect.not.stringContaining("\u001b") }),
		);
	});

	it("builds with a kid at the bound, and verifyJwt accepts what it signed — on every store", async () => {
		const kid = "k".repeat(MAX_KID_LENGTH);
		for (const store of [symmetric(kid), await asymmetric(kid), await remote(kid)]) {
			const now = Math.floor(Date.now() / 1000);
			const token = await store.sign({
				claims: { iss: ISSUER, sub: "user-1", iat: now, exp: now + 60 },
				header: { typ: "at+jwt" },
			});
			await expect(
				verifyJwt(token, store, {
					type: "access_token",
					expectedIssuer: ISSUER,
					revocation: "none",
				}),
			).resolves.toMatchObject({ payload: { sub: "user-1" } });
		}
	});
});
