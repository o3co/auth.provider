import { randomBytes } from "node:crypto";
import { expect, it } from "vitest";
import { credentialOf, freshHandle } from "../src/contract.ts";

const handle = randomBytes(32).toString("base64url");
const credential = {
	id: randomBytes(16).toString("base64url"),
	publicKey: randomBytes(77).toString("base64url"),
	signCount: 3,
	userHandle: handle,
	backupEligible: true,
	backedUp: false,
	transports: ["internal"],
};

it("reads a credential in the shape webauthn writes, and only its fields", () => {
	expect(credentialOf(credential)).toEqual(credential);
	expect(credentialOf({ ...credential, nickname: "laptop" })).toEqual(credential);
	const { transports: _, ...bare } = credential;
	expect(credentialOf(bare)).toEqual(bare);
});

it("reads nothing from a credential whose id, key or handle is not unpadded base64url within its limit", () => {
	for (const changed of [
		{ id: `${credential.id}=` },
		{ id: "" },
		{ id: Buffer.alloc(1024).toString("base64url") },
		{ publicKey: credential.publicKey.replace(/./, "+") },
		{ userHandle: Buffer.alloc(65).toString("base64url") },
		{ userHandle: `${handle.slice(0, -1)}B` },
	]) {
		expect(credentialOf({ ...credential, ...changed }), JSON.stringify(changed)).toBeUndefined();
	}
});

it("reads nothing from a credential with a count out of range or a field missing or mistyped", () => {
	for (const changed of [
		{ signCount: -1 },
		{ signCount: 1.5 },
		{ backupEligible: "yes" },
		{ backedUp: undefined },
		{ transports: "internal" },
	]) {
		expect(credentialOf({ ...credential, ...changed }), JSON.stringify(changed)).toBeUndefined();
	}
	for (const value of [undefined, null, "x", []]) expect(credentialOf(value)).toBeUndefined();
});

it("makes a user handle of 32 bytes from the randomness given, in unpadded base64url", () => {
	const asked: number[] = [];
	const made = freshHandle((n) => {
		asked.push(n);
		return new Uint8Array(n).fill(0xfb);
	});
	expect(asked).toEqual([32]);
	expect(made).toBe(Buffer.alloc(32, 0xfb).toString("base64url"));
	expect(made).not.toMatch(/[=+/]/);
});
