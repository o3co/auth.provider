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
 * A previous key verifies until its `expiresAt` and never after. So a keystore
 * refuses, when it is built, a previous entry whose `expiresAt` is not a Date
 * holding a valid time — an Invalid Date compares false both ways, so it
 * would read as "not yet retired" forever — and reads each date once, so the
 * caller changing that Date object afterwards moves no deadline. The same
 * rule holds on the symmetric, asymmetric and remote-signing stores.
 */

import { generateKeyPairSync, sign as nodeSign } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
	createAsymmetricKeyStore,
	createSymmetricKeyStore,
	ExpiredKidError,
} from "#/keys/KeyStore.mjs";
import { createRemoteSigningKeyStore } from "#/keys/remoteSigning.mjs";

const SECRET = "x".repeat(64);
const ed = generateKeyPairSync("ed25519");
const publicKeyPem = ed.publicKey.export({ type: "spki", format: "pem" }).toString();
const privateKeyPem = ed.privateKey.export({ type: "pkcs8", format: "pem" }).toString();
const signer = {
	sign: async (_kid: string, data: Uint8Array) =>
		new Uint8Array(nodeSign(null, data, ed.privateKey)),
};

const UNUSABLE: ReadonlyArray<readonly [string, unknown]> = [
	["an Invalid Date", new Date("not a date")],
	["an ISO string instead of a Date", "2099-01-01T00:00:00Z"],
	["epoch milliseconds instead of a Date", Date.now() + 600_000],
	["absent", undefined],
	["null", null],
	["an object that only looks like a Date", { getTime: () => Date.now() + 600_000 }],
];

const symmetric = (expiresAt: unknown) =>
	createSymmetricKeyStore(SECRET, "v1", [
		{ kid: "v0", secret: "y".repeat(64), expiresAt: expiresAt as Date },
	]);
const asymmetric = (expiresAt: unknown) =>
	createAsymmetricKeyStore({
		algorithm: "EdDSA",
		kid: "v1",
		privateKeyPem,
		publicKeyPem,
		previousKeys: [{ kid: "v0", publicKeyPem, expiresAt: expiresAt as Date }],
	});
const remote = (expiresAt: unknown) =>
	createRemoteSigningKeyStore({
		algorithm: "EdDSA",
		kid: "v1",
		signer,
		publicKeyPem,
		previousKeys: [{ kid: "v0", publicKeyPem, expiresAt: expiresAt as Date }],
	});

describe("a keystore refuses, when built, a previous key's expiresAt that is not a valid Date", () => {
	for (const [label, expiresAt] of UNUSABLE) {
		describe(label, () => {
			it("on the symmetric store, naming previousSecrets[0].expiresAt", () => {
				expect(() => symmetric(expiresAt)).toThrow(/previousSecrets\[0\]\.expiresAt/);
			});

			it("on the asymmetric store, naming previousKeys[0].expiresAt", async () => {
				await expect(asymmetric(expiresAt)).rejects.toThrow(/previousKeys\[0\]\.expiresAt/);
			});

			it("on the remote-signing store, naming previousKeys[0].expiresAt", async () => {
				await expect(remote(expiresAt)).rejects.toThrow(/previousKeys\[0\]\.expiresAt/);
			});
		});
	}
});

describe("a keystore reads each previous key's expiresAt once, when built", () => {
	const stores = [
		["symmetric", (d: Date) => Promise.resolve(symmetric(d))],
		["asymmetric", asymmetric],
		["remote-signing", remote],
	] as const;

	for (const [label, build] of stores) {
		describe(label, () => {
			it("keeps a retired key retired when the caller moves its Date afterwards", async () => {
				const expiresAt = new Date(Date.now() - 1_000);
				const store = await build(expiresAt);
				expiresAt.setTime(Date.now() + 86_400_000);
				await expect(store.getVerificationKey("v0")).rejects.toBeInstanceOf(ExpiredKidError);
				expect((await store.getVerificationKeys()).map((k) => k.kid)).toEqual(["v1"]);
			});

			it("keeps a key's deadline when the caller invalidates its Date afterwards", async () => {
				const deadline = Date.now() + 600_000;
				const expiresAt = new Date(deadline);
				const store = await build(expiresAt);
				expiresAt.setTime(Number.NaN);
				await expect(store.getVerificationKey("v0")).resolves.toBeDefined();
				const published = (await store.getVerificationKeys()).find((k) => k.kid === "v0");
				expect(published?.expiresAt?.getTime()).toBe(deadline);
			});

			it("hands out a copy of the deadline, so changing it moves nothing", async () => {
				const deadline = Date.now() - 1_000;
				const store = await build(new Date(deadline));
				const first = await store.getVerificationKey("v0").catch((e: unknown) => e);
				expect(first).toBeInstanceOf(ExpiredKidError);
				(first as ExpiredKidError).expiredAt.setTime(Date.now() + 86_400_000);
				const second = await store.getVerificationKey("v0").catch((e: unknown) => e);
				expect(second).toBeInstanceOf(ExpiredKidError);
				expect((second as ExpiredKidError).expiredAt.getTime()).toBe(deadline);
			});
		});
	}
});
