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
