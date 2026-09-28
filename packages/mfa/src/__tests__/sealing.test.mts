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

import { createHmac, randomBytes } from "node:crypto";
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
		expect(
			sealingOver([K1])
				.digestsFor("recovery_code")
				.matchesDigest(["x"], {
					keyId: 1 as unknown as string,
					digest: stored.digest,
				}),
		).toBe("key_unavailable");
	});

	it("never uses a sealing key as the HMAC key itself", () => {
		const stored = sealingOver([K1]).digestsFor("email").digest(["a"]);
		const raw = createHmac("sha256", K1.key).update("a").digest("base64url");
		expect(stored.digest).not.toBe(raw);
	});

	it("refuses parts that are not strings, and a kind it cannot bind to", () => {
		const digests = sealingOver([K1]).digestsFor("email");
		expect(() => digests.digest([1 as unknown as string])).toThrow(RangeError);
		expect(() => sealingOver([K1]).digestsFor("")).toThrow(RangeError);
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
