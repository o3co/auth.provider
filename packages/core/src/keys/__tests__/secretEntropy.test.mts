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
import { randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
	assertSecretEntropy,
	describeWeakSecret,
	MIN_SECRET_ENTROPY_BYTES,
	measureSecretEntropyBytes,
} from "#/keys/secretEntropy.mjs";

describe("MIN_SECRET_ENTROPY_BYTES", () => {
	it("is 32 bytes (256 bits)", () => {
		expect(MIN_SECRET_ENTROPY_BYTES).toBe(32);
	});
});

describe("measureSecretEntropyBytes", () => {
	it("measures an ordinary passphrase by its UTF-8 byte length", () => {
		// Contains '.', which is outside both the base64 and base64url
		// alphabets, so only the UTF-8 interpretation is plausible.
		expect(measureSecretEntropyBytes("abc.def")).toBe(7);
	});

	it("counts multi-byte UTF-8 characters as their encoded byte length", () => {
		// "パスワード." — 5 x 3-byte chars + '.'
		expect(measureSecretEntropyBytes("パスワード.")).toBe(16);
	});

	it("returns 0 for an empty string", () => {
		expect(measureSecretEntropyBytes("")).toBe(0);
	});

	it("measures a hex secret on its DECODED length, not its character count", () => {
		const hex = randomBytes(32).toString("hex"); // 64 characters
		expect(hex).toHaveLength(64);
		expect(measureSecretEntropyBytes(hex)).toBe(32);
	});

	it("rejects a 32-character hex secret as only 16 bytes of material", () => {
		const hex = randomBytes(16).toString("hex"); // 32 characters, 16 bytes
		expect(measureSecretEntropyBytes(hex)).toBe(16);
		expect(measureSecretEntropyBytes(hex)).toBeLessThan(MIN_SECRET_ENTROPY_BYTES);
	});

	it("measures a base64url secret on its decoded length", () => {
		const b64 = randomBytes(32).toString("base64url"); // 43 characters
		expect(b64).toHaveLength(43);
		expect(measureSecretEntropyBytes(b64)).toBe(32);
	});

	it("measures a padded standard-base64 secret on its decoded length", () => {
		const b64 = randomBytes(32).toString("base64"); // 44 characters incl. '='
		expect(b64).toHaveLength(44);
		expect(measureSecretEntropyBytes(b64)).toBe(32);
	});

	it("takes the SMALLEST plausible interpretation when several decodings apply", () => {
		// All-hex strings are simultaneously valid base64url. 64 hex characters
		// decode to 32 bytes as hex and 48 bytes as base64url; the conservative
		// (hex) reading is what counts.
		expect(measureSecretEntropyBytes("0".repeat(64))).toBe(32);
	});

	it("does not treat a string with a base64-alphabet-invalid length as base64", () => {
		// 21 characters: 21 % 4 === 1, which no base64 encoding can produce.
		// This is the umbrella E2E's old secret; it must measure as 21 UTF-8 bytes.
		expect(measureSecretEntropyBytes("test-secret-for-e2e--")).toBe(21);
	});

	it("measures a one-character secret as one byte", () => {
		expect(measureSecretEntropyBytes("x")).toBe(1);
	});
});

describe("measureSecretEntropyBytes — base64 padding must be well-formed", () => {
	// An encoder emits zero, one or two '=', and only where the body length
	// calls for it. Trimming any run of '=' would turn a passphrase that merely
	// ends in equals signs into a "valid" base64 body and score it at
	// three-quarters of its real length.

	it("accepts one '=' after a 3-character final group", () => {
		const b64 = randomBytes(32).toString("base64"); // 43 body + 1 pad
		expect(b64.endsWith("=")).toBe(true);
		expect(b64.endsWith("==")).toBe(false);
		expect(measureSecretEntropyBytes(b64)).toBe(32);
	});

	it("accepts two '=' after a 2-character final group", () => {
		const b64 = randomBytes(31).toString("base64"); // 42 body + 2 pad
		expect(b64.endsWith("==")).toBe(true);
		expect(measureSecretEntropyBytes(b64)).toBe(31);
	});

	it("rejects more than two '=' — 'abcd====' is not base64, so it reads as 8 raw bytes", () => {
		// Pre-fix this stripped all four, leaving the well-formed body "abcd"
		// and scoring 3 bytes.
		expect(measureSecretEntropyBytes("abcd====")).toBe(8);
	});

	it("rejects padding the body length does not call for ('abcd=')", () => {
		// A 4-character body is already a whole group; one '=' after it is
		// malformed, so the value reads as its 5 raw bytes.
		expect(measureSecretEntropyBytes("abcd=")).toBe(5);
	});

	it("rejects two '=' after a 3-character group ('abc==')", () => {
		expect(measureSecretEntropyBytes("abc==")).toBe(5);
	});

	it("does not punish a long passphrase that merely ends in equals signs", () => {
		// 44 characters, of which the last four are '='. The whole point of the
		// fix: this clears the floor on its raw length instead of being trimmed
		// to a 40-character body and scored 30 bytes.
		const passphrase = `${"a".repeat(40)}====`;
		expect(passphrase).toHaveLength(44);
		expect(measureSecretEntropyBytes(passphrase)).toBe(44);
		expect(() =>
			assertSecretEntropy(passphrase, {
				configKey: "session.secret",
				envVar: "SESSION_SECRET",
			}),
		).not.toThrow();
	});

	it("returns the raw reading for a value that is only padding", () => {
		expect(measureSecretEntropyBytes("==")).toBe(2);
	});
});

describe("assertSecretEntropy", () => {
	const requirement = {
		configKey: "oauth.jwt.signingKey.local.secret",
		envVar: "OAUTH_JWT_SECRET",
	};

	it("accepts a secret at exactly the floor", () => {
		// The '!' keeps the value outside the base64/base64url alphabets, so
		// the UTF-8 reading (32 bytes) is the only plausible one.
		expect(() => assertSecretEntropy(`${"a".repeat(31)}!`, requirement)).not.toThrow();
	});

	it("accepts a 64-character hex secret (32 decoded bytes)", () => {
		expect(() => assertSecretEntropy(randomBytes(32).toString("hex"), requirement)).not.toThrow();
	});

	it("rejects a one-character secret", () => {
		expect(() => assertSecretEntropy("x", requirement)).toThrow(/at least 32 bytes/i);
	});

	it("rejects a secret one byte below the floor", () => {
		expect(() => assertSecretEntropy(`${"a".repeat(30)}!`, requirement)).toThrow(
			/at least 32 bytes/i,
		);
	});

	it("rejects an all-alphanumeric 32-character secret, which is base64-shaped (24 bytes)", () => {
		// [A-Za-z0-9]{32} is a valid base64 body, so the conservative reading is
		// 24 bytes — and an operator who picked 32 alphanumerics really does only
		// have ~190 bits, whether or not they meant it as base64.
		expect(() => assertSecretEntropy("a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6", requirement)).toThrow(
			/at least 32 bytes/i,
		);
	});

	it("rejects a 32-character hex secret even though it is 32 characters long", () => {
		expect(() => assertSecretEntropy(randomBytes(16).toString("hex"), requirement)).toThrow(
			/at least 32 bytes/i,
		);
	});

	it("names the config key and the environment variable in the failure", () => {
		let message = "";
		try {
			assertSecretEntropy("x", requirement);
		} catch (err) {
			message = (err as Error).message;
		}
		expect(message).toContain("oauth.jwt.signingKey.local.secret");
		expect(message).toContain("OAUTH_JWT_SECRET");
	});

	it("tells the operator how to generate a compliant secret", () => {
		let message = "";
		try {
			assertSecretEntropy("x", requirement);
		} catch (err) {
			message = (err as Error).message;
		}
		expect(message).toMatch(/openssl rand -hex 32/);
	});

	it("never echoes the rejected secret back in the message", () => {
		let message = "";
		try {
			assertSecretEntropy("hunter2-do-not-leak", requirement);
		} catch (err) {
			message = (err as Error).message;
		}
		expect(message).not.toContain("hunter2-do-not-leak");
	});
});

describe("describeWeakSecret", () => {
	it("reports the measured byte count so an operator can see how short it is", () => {
		const message = describeWeakSecret(7, {
			configKey: "session.secret",
			envVar: "SESSION_SECRET",
		});
		expect(message).toContain("session.secret");
		expect(message).toContain("SESSION_SECRET");
		expect(message).toMatch(/\b7\b/);
	});

	it("explains that encoded secrets are measured on their decoded length", () => {
		const message = describeWeakSecret(16, {
			configKey: "session.secret",
			envVar: "SESSION_SECRET",
		});
		expect(message).toMatch(/decoded/i);
	});
});
