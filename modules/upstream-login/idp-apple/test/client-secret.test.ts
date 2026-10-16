import { generateKeyPairSync, type KeyObject } from "node:crypto";
import { decodeProtectedHeader, jwtVerify, SignJWT } from "jose";
import { describe, expect, it, vi } from "vitest";
import { secretOf } from "../src/client-secret/secret.ts";

const pair = () => generateKeyPairSync("ec", { namedCurve: "P-256" });
const parts = (key: KeyObject) => ({
	teamId: "TEAM",
	keyId: "KEY1",
	clientId: "com.example.web",
	key,
	lifetimeMs: 300_000,
	audience: "https://appleid.apple.com",
});

describe("client-secret", () => {
	it("signs a short JWT naming the team, the client and Apple, on the clock given", async () => {
		const { privateKey, publicKey } = pair();
		const clock = { now: () => 1_800_000_000_500 };
		const jwt = await secretOf(parts(privateKey), clock).current();
		expect(decodeProtectedHeader(jwt)).toEqual({ alg: "ES256", kid: "KEY1" });
		const { payload } = await jwtVerify(jwt, publicKey, {
			currentDate: new Date(clock.now()),
		});
		expect(payload).toEqual({
			iss: "TEAM",
			sub: "com.example.web",
			aud: "https://appleid.apple.com",
			iat: 1_800_000_000,
			exp: 1_800_000_300,
		});
	});

	it("holds the secret until half its life is spent, and shares one signing between requests", async () => {
		let now = 1_800_000_000_000;
		const held = secretOf(parts(pair().privateKey), { now: () => now });
		const [first, same] = await Promise.all([held.current(), held.current()]);
		expect(same).toBe(first);
		now += 149_999;
		expect(await held.current()).toBe(first);
		now += 1;
		expect(await held.current()).not.toBe(first);
	});

	it("never hands out a secret made under another key", async () => {
		const at = { currentDate: new Date(1_800_000_000_000) };
		const [one, other] = [pair(), pair()];
		let key = one.privateKey;
		const held = secretOf(
			{
				...parts(key),
				get key() {
					return key;
				},
			},
			{ now: () => at.currentDate.getTime() },
		);
		await jwtVerify(await held.current(), one.publicKey, at);
		key = other.privateKey;
		await jwtVerify(await held.current(), other.publicKey, at);
	});

	it("keeps no signing that failed", async () => {
		const failed = vi.spyOn(SignJWT.prototype, "sign").mockRejectedValueOnce(new Error("hsm"));
		const held = secretOf(parts(pair().privateKey), { now: () => 1_800_000_000_000 });
		await expect(held.current()).rejects.toThrow();
		await expect(held.current()).resolves.toMatch(/^ey/);
		failed.mockRestore();
	});
});
