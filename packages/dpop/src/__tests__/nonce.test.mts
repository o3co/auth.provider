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

import { describe, expect, it } from "vitest";
import { createDPoPNonceIssuer } from "#/nonce.mjs";

/**
 * #530 — server-provided DPoP nonces, stateless: a time bucket and an HMAC
 * under a shared secret. What matters is that only this server's secret can
 * mint one, that one from the previous bucket still counts, and that older
 * or foreign ones do not.
 */
const SECRET = "a-dpop-nonce-secret-of-at-least-32-bytes!!";

describe("createDPoPNonceIssuer (#530)", () => {
	it("issues a nonce it verifies, and one from the previous bucket still counts", () => {
		// Aligned to a bucket start (3_333_334 * 300 s), so the arithmetic below
		// crosses boundaries exactly where the comments say it does.
		let t = 3_333_334 * 300 * 1000;
		const issuer = createDPoPNonceIssuer({ secret: SECRET, ttlSeconds: 300, now: () => t });
		const nonce = issuer.issue();
		expect(issuer.verify(nonce)).toBe(true);

		t += 299_000;
		expect(issuer.issue()).toBe(nonce); // same bucket
		t += 1_000; // the bucket turns
		const next = issuer.issue();
		expect(next).not.toBe(nonce);
		expect(issuer.verify(nonce)).toBe(true); // previous bucket, still accepted
		expect(issuer.verify(next)).toBe(true);

		t += 300_000; // two buckets on: the old one is out
		expect(issuer.verify(nonce)).toBe(false);
		expect(issuer.verify(next)).toBe(true);
	});

	it("refuses a nonce under another secret, a tampered one, one from the future, and garbage", () => {
		const t = 3_333_334 * 300 * 1000;
		const issuer = createDPoPNonceIssuer({ secret: SECRET, ttlSeconds: 300, now: () => t });
		const other = createDPoPNonceIssuer({
			secret: "another-secret-that-is-also-32-bytes-long",
			ttlSeconds: 300,
			now: () => t,
		});
		expect(issuer.verify(other.issue())).toBe(false);

		const nonce = issuer.issue();
		const [bucket, mac] = nonce.split(".") as [string, string];
		expect(issuer.verify(`${bucket}.${mac.slice(0, -2)}AA`)).toBe(false);
		expect(issuer.verify(`${Number(bucket) + 1}.${mac}`)).toBe(false);
		expect(issuer.verify(`${Number(bucket) - 2}.${mac}`)).toBe(false);
		for (const junk of [
			"",
			".",
			"abc",
			`${bucket}`,
			`${bucket}.`,
			"x.y",
			`${bucket}.${mac}.extra`,
		]) {
			expect(issuer.verify(junk), junk).toBe(false);
		}
	});

	it("is the same nonce on every replica that shares the secret", () => {
		const t = 3_333_334 * 300 * 1000;
		const a = createDPoPNonceIssuer({ secret: SECRET, now: () => t });
		const b = createDPoPNonceIssuer({ secret: SECRET, now: () => t });
		expect(a.issue()).toBe(b.issue());
		expect(b.verify(a.issue())).toBe(true);
	});

	it("refuses to build on a short secret or a bad ttl", () => {
		expect(() => createDPoPNonceIssuer({ secret: "short" })).toThrow(/at least 32 bytes/);
		expect(() => createDPoPNonceIssuer({ secret: SECRET, ttlSeconds: 0 })).toThrow(/ttlSeconds/);
		expect(() => createDPoPNonceIssuer({ secret: SECRET, ttlSeconds: 1.5 })).toThrow(/ttlSeconds/);
	});
});
