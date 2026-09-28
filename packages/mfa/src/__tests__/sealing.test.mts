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
 * Secrets at rest (the MFA ADR's D11), over core's key-ring envelope:
 *
 * - a factor's data is sealed under the purpose `o3co:mfa:factor` with its
 *   record — subject, factor id, kind, length-prefixed — in the authenticated
 *   data, so data copied to another subject, another id or relabelled as
 *   another kind does not open: `unreadable`;
 * - a ceremony's state (a challenge, a pending enrollment) is sealed with the
 *   transaction id in the authenticated data;
 * - a key that has left the ring is `key_unavailable` — never `unreadable`,
 *   which no key would cure — and opening never throws on what it is handed;
 * - opening under a key that is no longer first says so once per key id
 *   (`mfa_factor_sealed_with_retired_key`), so an operator knows the key is
 *   still needed;
 * - codes compared and never recovered are keyed digests (HMAC-SHA-256)
 *   carrying their key id, bound to the factor's kind, compared in constant
 *   time; a digest whose key left the ring cannot be judged.
 */

import { createHmac, hkdfSync, randomBytes } from "node:crypto";
import { type Logger, type SealingKeyRing, sealWithKeyRing } from "@o3co/auth-provider-core";
import { describe, expect, it, vi } from "vitest";
import {
	createMfaSealing,
	MFA_CHALLENGE_SEALING_PURPOSE,
	MFA_ENROLLMENT_SEALING_PURPOSE,
	MFA_FACTOR_SEALING_PURPOSE,
} from "#/sealing.mjs";

const K1 = { id: "k1", key: randomBytes(32) };
const K2 = { id: "k2", key: randomBytes(32) };

/** A logger that records each call. */
function recordingLogger() {
	const lines: { level: string; fields: Record<string, unknown>; event: unknown }[] = [];
	const record =
		(level: string) =>
		(fields: Record<string, unknown>, event?: unknown): void => {
			lines.push({ level, fields, event });
		};
	const logger = {
		trace: record("trace"),
		debug: record("debug"),
		info: record("info"),
		warn: record("warn"),
		error: record("error"),
		fatal: record("fatal"),
		child: () => logger,
	} as unknown as Logger;
	return { logger, lines };
}

const sealingOver = (ring: SealingKeyRing, logger?: Logger) =>
	createMfaSealing({ ring, ...(logger ? { logger } : {}) });

const RECORD = { subject: "u-alice", id: "f-1", kind: "totp" } as const;

/** `parts`, each after its UTF-8 length as a 32-bit big-endian number: D11's record. */
const lengthPrefixed = (parts: readonly string[]): Buffer =>
	Buffer.concat(
		parts.flatMap((part) => {
			const bytes = Buffer.from(part, "utf8");
			const length = Buffer.alloc(4);
			length.writeUInt32BE(bytes.length);
			return [length, bytes];
		}),
	);

/** `plaintext` sealed as a factor's data for {@link RECORD} would be, by core's envelope directly. */
const sealedAsFactorData = (plaintext: string) =>
	sealWithKeyRing(plaintext, [K1], {
		purpose: "o3co:mfa:factor",
		record: lengthPrefixed([RECORD.subject, RECORD.id, RECORD.kind]),
	});

const DATA = { secret: "JBSWY3DPEHPK3PXP", lastUsedStep: 42, nested: { a: [1, 2] } };

describe("a factor's data, sealed to its record (D11)", () => {
	it("round-trips through JSON, naming the key that sealed it", () => {
		const sealing = sealingOver([K1, K2]);
		const sealed = sealing.sealFactorData(RECORD, DATA);
		expect(sealed.startsWith("v2.")).toBe(true);
		expect(sealed).not.toContain(DATA.secret);
		expect(sealing.openFactorData(RECORD, sealed)).toEqual({
			state: "ok",
			value: DATA,
			keyId: "k1",
		});
	});

	it("seals under the purpose o3co:mfa:factor, with subject, id and kind length-prefixed as the record", () => {
		expect(MFA_FACTOR_SEALING_PURPOSE).toBe("o3co:mfa:factor");
		// Sealed by core's envelope directly, as D11 states the binding: it opens.
		const sealed = sealedAsFactorData(JSON.stringify(DATA));
		expect(sealingOver([K1]).openFactorData(RECORD, sealed)).toMatchObject({
			state: "ok",
			value: DATA,
		});
	});

	it("does not open for another subject, another id or another kind", () => {
		const sealing = sealingOver([K1]);
		const sealed = sealing.sealFactorData(RECORD, DATA);
		for (const other of [
			{ ...RECORD, subject: "u-mallory" },
			{ ...RECORD, id: "f-2" },
			{ ...RECORD, kind: "email" },
			// The length prefixes keep one part from absorbing its neighbour.
			{ subject: "u-alicef", id: "-1", kind: "totp" },
			{ subject: "u-alice", id: "f-1t", kind: "otp" },
		]) {
			expect(sealing.openFactorData(other, sealed), JSON.stringify(other)).toEqual({
				state: "unreadable",
			});
		}
	});

	it("answers key_unavailable when the key that sealed it has left the ring, naming it", () => {
		const sealed = sealingOver([K1]).sealFactorData(RECORD, DATA);
		expect(sealingOver([K2]).openFactorData(RECORD, sealed)).toEqual({
			state: "key_unavailable",
			keyId: "k1",
		});
	});

	it("opens under a key that is no longer first, and says so once per key id, at info", () => {
		const sealedUnderK1 = sealingOver([K1]).sealFactorData(RECORD, DATA);
		const { logger, lines } = recordingLogger();
		const rotated = sealingOver([K2, K1], logger);
		for (let i = 0; i < 3; i++) {
			expect(rotated.openFactorData(RECORD, sealedUnderK1)).toEqual({
				state: "ok",
				value: DATA,
				keyId: "k1",
			});
		}
		expect(lines).toEqual([
			{ level: "info", fields: { keyId: "k1" }, event: "mfa_factor_sealed_with_retired_key" },
		]);
		// What it seals now is under the first key, and says nothing when opened.
		const resealed = rotated.sealFactorData(RECORD, DATA);
		expect(rotated.openFactorData(RECORD, resealed)).toMatchObject({ keyId: "k2" });
		expect(lines).toHaveLength(1);
	});

	it("never throws on what it is handed to open: anything that is not its envelope is unreadable", () => {
		const sealing = sealingOver([K1]);
		const notAnObject = sealedAsFactorData("[1,2]");
		const notJson = sealedAsFactorData("{");
		for (const sealed of [undefined, null, 42, {}, "", "v2", "v1.a.b.c.d", notAnObject, notJson]) {
			expect(sealing.openFactorData(RECORD, sealed), String(sealed)).toEqual({
				state: "unreadable",
			});
		}
		const good = sealing.sealFactorData(RECORD, DATA);
		for (const binding of [
			{ ...RECORD, subject: undefined },
			{ ...RECORD, id: 1 },
			{ ...RECORD, kind: null },
		]) {
			expect(sealing.openFactorData(binding as never, good)).toEqual({ state: "unreadable" });
		}
	});

	it("refuses to seal what is not a JSON object, or for a record it cannot name", () => {
		const sealing = sealingOver([K1]);
		for (const data of [null, [], "text", 1]) {
			expect(() => sealing.sealFactorData(RECORD, data as never)).toThrow(RangeError);
		}
		for (const binding of [
			{ ...RECORD, subject: "" },
			{ ...RECORD, id: undefined },
			{ ...RECORD, kind: 1 },
		]) {
			expect(() => sealing.sealFactorData(binding as never, DATA)).toThrow(RangeError);
		}
	});
});

describe("a ceremony's state, sealed to its transaction (D11)", () => {
	const CHALLENGE = { transactionId: "tx-1", kind: "webauthn", use: "challenge" } as const;
	const STATE = { challenge: "abc", expected: ["x"] };

	it("round-trips, and does not open for another transaction", () => {
		const sealing = sealingOver([K1]);
		const sealed = sealing.sealState(CHALLENGE, STATE);
		expect(sealing.openState(CHALLENGE, sealed)).toEqual({
			state: "ok",
			value: STATE,
			keyId: "k1",
		});
		expect(sealing.openState({ ...CHALLENGE, transactionId: "tx-2" }, sealed)).toEqual({
			state: "unreadable",
		});
	});

	it("is bound to its kind and to what it is: a challenge is not a pending enrollment, nor factor data", () => {
		expect(MFA_CHALLENGE_SEALING_PURPOSE).toBe("o3co:mfa:challenge");
		expect(MFA_ENROLLMENT_SEALING_PURPOSE).toBe("o3co:mfa:enrollment");
		const sealing = sealingOver([K1]);
		const sealed = sealing.sealState(CHALLENGE, STATE);
		expect(sealing.openState({ ...CHALLENGE, kind: "email" }, sealed)).toEqual({
			state: "unreadable",
		});
		expect(sealing.openState({ ...CHALLENGE, use: "enrollment" }, sealed)).toEqual({
			state: "unreadable",
		});
		expect(
			sealing.openFactorData({ subject: "tx-1", id: "webauthn", kind: "challenge" }, sealed),
		).toEqual({ state: "unreadable" });
	});

	it("seals only a challenge's or a pending enrollment's state", () => {
		const sealing = sealingOver([K1]);
		const other = { ...CHALLENGE, use: "other" } as unknown as typeof CHALLENGE;
		expect(() => sealing.sealState(other, STATE)).toThrow(RangeError);
		expect(sealing.openState(other, sealing.sealState(CHALLENGE, STATE))).toEqual({
			state: "unreadable",
		});
	});

	it("answers key_unavailable for a dropped key, and unreadable for anything else", () => {
		const sealed = sealingOver([K1]).sealState(CHALLENGE, STATE);
		expect(sealingOver([K2]).openState(CHALLENGE, sealed)).toEqual({
			state: "key_unavailable",
			keyId: "k1",
		});
		for (const value of [undefined, 1, "v2.x"]) {
			expect(sealingOver([K1]).openState(CHALLENGE, value)).toEqual({ state: "unreadable" });
		}
	});
});

describe("keyed digests (D7, D11)", () => {
	it("digests under the first key, naming it, the same parts the same way", () => {
		const digests = sealingOver([K1, K2]).digestsFor("email");
		const one = digests.digest(["tx-1", "f-1", "123456"]);
		expect(one.keyId).toBe("k1");
		expect(one.digest).toMatch(/^[A-Za-z0-9_-]{43}$/);
		expect(digests.digest(["tx-1", "f-1", "123456"])).toEqual(one);
		expect(digests.matchesDigest(["tx-1", "f-1", "123456"], one)).toBe("match");
		expect(digests.matchesDigest(["tx-1", "f-1", "123457"], one)).toBe("mismatch");
	});

	it("binds a digest to the factor's kind, and each part to its place", () => {
		const sealing = sealingOver([K1]);
		const stored = sealing.digestsFor("email").digest(["a", "b"]);
		expect(sealing.digestsFor("recovery_code").matchesDigest(["a", "b"], stored)).toBe("mismatch");
		expect(sealing.digestsFor("email").matchesDigest(["ab", ""], stored)).toBe("mismatch");
		expect(sealing.digestsFor("email").matchesDigest(["a", "b", ""], stored)).toBe("mismatch");
	});

	it("keeps matching after rotation while the key stays in the ring, and cannot judge one whose key left", () => {
		const stored = sealingOver([K1]).digestsFor("recovery_code").digest(["ABCD1234EFGH5678"]);
		expect(
			sealingOver([K2, K1]).digestsFor("recovery_code").matchesDigest(["ABCD1234EFGH5678"], stored),
		).toBe("match");
		expect(
			sealingOver([K2]).digestsFor("recovery_code").matchesDigest(["ABCD1234EFGH5678"], stored),
		).toBe("key_unavailable");
	});

	it("throws on a stored digest that is not { keyId, digest }: key_unavailable means a key is missing, and a malformed record is never a wrong code", () => {
		const digests = sealingOver([K1]).digestsFor("email");
		const good = digests.digest(["a"]);
		for (const stored of [
			null,
			undefined,
			{},
			"k1",
			{ keyId: 1, digest: good.digest },
			{ keyId: "has space", digest: good.digest },
			{ keyId: "k1" },
			{ keyId: "k1", digest: 1 },
			{ keyId: "k1", digest: "" },
			{ keyId: "k1", digest: `${good.digest}=` },
			{ keyId: "k1", digest: good.digest.slice(1) },
		]) {
			let thrown: unknown;
			try {
				digests.matchesDigest(["a"], stored as never);
			} catch (error) {
				thrown = error;
			}
			expect(thrown, JSON.stringify(stored)).toBeInstanceOf(RangeError);
			expect((thrown as Error).message).not.toContain(good.digest);
		}
		// Well-formed, under a key the ring does not hold: that key is missing.
		expect(digests.matchesDigest(["a"], { keyId: "k9", digest: good.digest })).toBe(
			"key_unavailable",
		);
	});

	it("is HMAC-SHA-256, keyed by HKDF-SHA-256 from the ring key (info o3co:mfa:digest), over the kind and the parts length-prefixed, base64url — a format at rest for as long as a recovery code", () => {
		// A fixed key: the bytes 0x00 to 0x1f.
		const key = Buffer.from(Array.from({ length: 32 }, (_, index) => index));
		// kind "email", then "tx-1", "f-1", "123456": each after its length as
		// a 32-bit big-endian number, spelled out.
		const input = Buffer.from(
			"00000005656d61696c" + "0000000474782d31" + "00000003662d31" + "00000006313233343536",
			"hex",
		);
		const digestKey = Buffer.from(hkdfSync("sha256", key, Buffer.alloc(0), "o3co:mfa:digest", 32));
		const expected = createHmac("sha256", digestKey).update(input).digest("base64url");
		// The answer, as a literal: a change to any part of the format fails here.
		expect(expected).toBe("gi4UdFcuz4TVZjc1-WHOFk3EHl6KVtbWSFHEvr_ceGE");
		const digests = sealingOver([{ id: "fixed", key }]).digestsFor("email");
		expect(digests.digest(["tx-1", "f-1", "123456"])).toEqual({ keyId: "fixed", digest: expected });
		// Never the ring key itself as the HMAC key, over the same input.
		expect(expected).not.toBe(createHmac("sha256", key).update(input).digest("base64url"));
	});

	it("refuses parts that are not strings, and a kind it cannot bind to", () => {
		const digests = sealingOver([K1]).digestsFor("email");
		expect(() => digests.digest([1 as unknown as string])).toThrow(RangeError);
		expect(() => sealingOver([K1]).digestsFor("")).toThrow(RangeError);
	});
});

describe("text that is not well-formed: a binding or a digest must be one-to-one", () => {
	// Buffer.from(text, "utf8") writes a lone surrogate as U+FFFD's bytes, so
	// "\uD800", "\uDC00" and "\uFFFD" would be one binding and one digest.
	const LONE = ["\uD800", "\uDC00"];

	it("refuses to seal to a binding with a lone surrogate, and never opens for one", () => {
		const sealing = sealingOver([K1]);
		for (const field of ["subject", "id", "kind"] as const) {
			const replaced = { ...RECORD, [field]: `x\uFFFD` };
			const sealed = sealing.sealFactorData(replaced, DATA);
			for (const lone of LONE) {
				const binding = { ...RECORD, [field]: `x${lone}` };
				expect(() => sealing.sealFactorData(binding, DATA), `${field} ${lone}`).toThrow(RangeError);
				expect(sealing.openFactorData(binding, sealed), `${field} ${lone}`).toEqual({
					state: "unreadable",
				});
			}
		}
		for (const field of ["transactionId", "kind"] as const) {
			const binding = { transactionId: "tx-1", kind: "webauthn", use: "challenge" } as const;
			const sealed = sealing.sealState({ ...binding, [field]: "x\uFFFD" }, DATA);
			for (const lone of LONE) {
				const bad = { ...binding, [field]: `x${lone}` };
				expect(() => sealing.sealState(bad, DATA), `${field} ${lone}`).toThrow(RangeError);
				expect(sealing.openState(bad, sealed), `${field} ${lone}`).toEqual({
					state: "unreadable",
				});
			}
		}
	});

	it("refuses a digest over parts, or bound to a kind, that are not well-formed", () => {
		const digests = sealingOver([K1]).digestsFor("email");
		const stored = digests.digest(["\uFFFD"]);
		for (const lone of LONE) {
			expect(() => digests.digest([lone])).toThrow(RangeError);
			expect(() => digests.matchesDigest([lone], stored)).toThrow(RangeError);
			expect(() => sealingOver([K1]).digestsFor(`email${lone}`)).toThrow(RangeError);
		}
	});
});

describe("what is sealed is what opening gives back", () => {
	const SECRET_TEXT = "S3CR3T-VALUE";

	it("refuses, quoting nothing, a value that is not a JSON object of JSON values", () => {
		const sealing = sealingOver([K1]);
		const cycle: Record<string, unknown> = { secret: SECRET_TEXT };
		cycle.self = cycle;
		class Secret {
			readonly secret = SECRET_TEXT;
		}
		for (const [label, value] of [
			["a Date", new Date(0)],
			["a toJSON that answers a string", { secret: SECRET_TEXT, toJSON: () => SECRET_TEXT }],
			["a toJSON that answers an object", { toJSON: () => ({ secret: SECRET_TEXT }) }],
			["a Map", new Map([["secret", SECRET_TEXT]])],
			["a BigInt inside", { secret: SECRET_TEXT, n: 1n }],
			["a cycle", cycle],
			["a class instance", new Secret()],
			["a Map inside", { secret: SECRET_TEXT, m: new Map([["a", 1]]) }],
			["a Date inside", { secret: SECRET_TEXT, at: new Date(0) }],
			["NaN inside", { secret: SECRET_TEXT, n: Number.NaN }],
			["Infinity inside", { secret: SECRET_TEXT, n: Number.POSITIVE_INFINITY }],
			["a function inside", { secret: SECRET_TEXT, f: () => SECRET_TEXT }],
			["undefined in a list", { secret: SECRET_TEXT, list: [1, undefined] }],
			// biome-ignore lint/suspicious/noSparseArray: a hole is what this case is
			["a hole in a list", { secret: SECRET_TEXT, list: [1, , 2] }],
			[
				"a getter that throws",
				{
					get secret(): string {
						throw new Error(SECRET_TEXT);
					},
				},
			],
		] as const) {
			for (const seal of [
				() => sealing.sealFactorData(RECORD, value as never),
				() =>
					sealing.sealState(
						{ transactionId: "tx-1", kind: "totp", use: "enrollment" },
						value as never,
					),
			]) {
				let thrown: unknown;
				try {
					seal();
				} catch (error) {
					thrown = error;
				}
				expect(thrown, label).toBeInstanceOf(RangeError);
				expect((thrown as Error).message, label).not.toContain(SECRET_TEXT);
			}
		}
	});

	it("seals nested JSON, and leaves out a property whose value is undefined, as JSON does", () => {
		const sealing = sealingOver([K1]);
		const value = { a: undefined, b: [1, "x", null, { c: true, d: -0.5 }], e: {} };
		expect(sealing.openFactorData(RECORD, sealing.sealFactorData(RECORD, value))).toEqual({
			state: "ok",
			value: { b: [1, "x", null, { c: true, d: -0.5 }], e: {} },
			keyId: "k1",
		});
	});
});

describe("the ring it is built over", () => {
	it("is refused empty or unusable, as the sealing key ring", () => {
		expect(() => createMfaSealing({ ring: [] })).toThrow(RangeError);
		expect(() => createMfaSealing({ ring: [{ id: "k1", key: randomBytes(16) }] })).toThrow(
			RangeError,
		);
	});

	it("says what it says through core's consoleLogger when it is given no logger", () => {
		const info = vi.spyOn(console, "info").mockImplementation(() => {});
		try {
			const sealed = sealingOver([K1]).sealFactorData(RECORD, DATA);
			expect(sealingOver([K2, K1]).openFactorData(RECORD, sealed)).toMatchObject({ state: "ok" });
			expect(info.mock.calls).toEqual([[{ keyId: "k1" }, "mfa_factor_sealed_with_retired_key"]]);
		} finally {
			info.mockRestore();
		}
	});
});
