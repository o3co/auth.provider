import { randomBytes } from "node:crypto";
import { expect, it } from "vitest";
import { nonces } from "../src/nonce.ts";

it("makes a nonce of one bucket, whatever the clock does between its reads", () => {
	const secret = randomBytes(32);
	// Each read of the clock moves it on a whole bucket: a nonce read twice would mix two buckets.
	let at = 0;
	const issued = nonces(secret, 1000, () => {
		at += 1000;
		return at;
	}).issue();
	const bucket = Number(issued.split(".")[0]);
	expect(nonces(secret, 1000, () => bucket * 1000).verify(issued)).toBe(true);
});

it("makes a nonce no one foresees without the shared secret: a 256-bit MAC over its bucket, another under another secret, a new one each bucket [rfc9449-8-a]", () => {
	const secret = randomBytes(32);
	let at = 5_000;
	const issuing = nonces(secret, 1000, () => at);
	const current = issuing.issue();
	const [bucket, mac] = current.split(".");
	expect(Buffer.from(mac ?? "", "base64url")).toHaveLength(32);
	expect(nonces(randomBytes(32), 1000, () => at).issue()).not.toBe(current);
	at += 1000;
	const next = issuing.issue();
	expect(next.split(".")[1]).not.toBe(mac);
	// The next bucket's nonce guessed from the current one is not taken.
	expect(issuing.verify(`${Number(bucket) + 1}.${mac}`)).toBe(false);
	expect(issuing.verify(next)).toBe(true);
});
