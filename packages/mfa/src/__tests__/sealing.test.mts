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
 * Secrets at rest, over core's key-ring envelope. A factor's data is sealed
 * with its record (subject, factor id, kind, length-prefixed) in the
 * authenticated data, and a ceremony's state with its transaction id. Codes
 * compared and never recovered are keyed digests (HMAC-SHA-256) that carry
 * their key id, are bound to the factor's kind and are compared in constant
 * time. A key that has left the ring is `key_unavailable`, never `unreadable`,
 * which no key would cure. Opening under a key that is no longer first says so
 * once per key id (`mfa_factor_sealed_with_retired_key`), so an operator knows
 * the key is still needed. See ADR 2026-09-25-multi-factor-authentication,
 * "Secrets at rest".
 */

import { createHmac, hkdfSync, randomBytes } from "node:crypto";
import { type Logger, type SealingKeyRing, sealWithKeyRing } from "@o3co/auth-provider-core";
import { describe, expect, it, vi } from "vitest";
import {
	copyFactorValue,
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

/** `parts`, each after its UTF-8 length as a 32-bit big-endian number: the record's encoding. */
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

describe("a factor's data, sealed to its record", () => {
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
		// Sealed by core's envelope directly, with the binding the ADR states: it opens.
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

describe("a ceremony's state, sealed to its transaction", () => {
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

	it("reads a binding's every part once, by name", () => {
		const sealing = sealingOver([K1]);
		const reads = { transactionId: 0, kind: 0, use: 0 };
		class Binding {
			get transactionId(): string {
				reads.transactionId += 1;
				return CHALLENGE.transactionId;
			}
			get kind(): string {
				reads.kind += 1;
				return CHALLENGE.kind;
			}
			get use(): "enrollment" {
				reads.use += 1;
				return "enrollment";
			}
		}
		const sealed = sealing.sealState(new Binding(), STATE);
		expect(reads).toEqual({ transactionId: 1, kind: 1, use: 1 });
		expect(sealing.openState(new Binding(), sealed)).toMatchObject({ state: "ok" });
		expect(reads).toEqual({ transactionId: 2, kind: 2, use: 2 });
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

describe("keyed digests", () => {
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

	it("matches a digest made under a key that is no longer first, and says so once per key id, at info, beside what sealed data says of the same key — so both are counted before the key is retired", () => {
		const stored = sealingOver([K1]).digestsFor("recovery_code").digest(["ABCD1234EFGH5678"]);
		const sealedUnderK1 = sealingOver([K1]).sealFactorData(RECORD, DATA);
		const { logger, lines } = recordingLogger();
		const rotated = sealingOver([K2, K1], logger);
		expect(rotated.openFactorData(RECORD, sealedUnderK1)).toMatchObject({ state: "ok" });
		for (let i = 0; i < 3; i++) {
			expect(rotated.digestsFor("recovery_code").matchesDigest(["ABCD1234EFGH5678"], stored)).toBe(
				"match",
			);
		}
		expect(rotated.digestsFor("recovery_code").matchesDigest(["ABCD1234EFGH5679"], stored)).toBe(
			"mismatch",
		);
		expect(lines).toEqual([
			{ level: "info", fields: { keyId: "k1" }, event: "mfa_factor_sealed_with_retired_key" },
			{ level: "info", fields: { keyId: "k1" }, event: "mfa_digest_made_with_retired_key" },
		]);
		// A digest under the first key says nothing.
		const current = rotated.digestsFor("recovery_code").digest(["ABCD1234EFGH5678"]);
		expect(rotated.digestsFor("recovery_code").matchesDigest(["ABCD1234EFGH5678"], current)).toBe(
			"match",
		);
		expect(lines).toHaveLength(2);
	});

	it("says a stored digest names a key that is no longer first before it compares it, so a first comparison that mismatches still counts the key", () => {
		const stored = sealingOver([K1]).digestsFor("recovery_code").digest(["ABCD1234EFGH5678"]);
		const { logger, lines } = recordingLogger();
		const rotated = sealingOver([K2, K1], logger);
		expect(rotated.digestsFor("recovery_code").matchesDigest(["WRONG0000WRONG00"], stored)).toBe(
			"mismatch",
		);
		expect(lines).toEqual([
			{ level: "info", fields: { keyId: "k1" }, event: "mfa_digest_made_with_retired_key" },
		]);
		// Not said for a key the ring no longer holds: that is key_unavailable's.
		expect(sealingOver([K2], logger).digestsFor("recovery_code").matchesDigest(["X"], stored)).toBe(
			"key_unavailable",
		);
		expect(lines).toHaveLength(1);
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

	it("reads a stored digest's fields by name, once each, a class's instance with getters among them", () => {
		const digests = sealingOver([K1]).digestsFor("email");
		const good = digests.digest(["a"]);
		const reads = { keyId: 0, digest: 0 };
		class StoredDigest {
			get keyId(): string {
				reads.keyId += 1;
				return good.keyId;
			}
			get digest(): string {
				reads.digest += 1;
				return good.digest;
			}
		}
		expect(digests.matchesDigest(["a"], new StoredDigest())).toBe("match");
		expect(reads).toEqual({ keyId: 1, digest: 1 });
	});

	it("reads each part once, from any list — an Array subclass, an index a getter answers — and digests what it read", () => {
		const digests = sealingOver([K1]).digestsFor("email");
		let reads = 0;
		class Parts extends Array<string> {}
		const parts = Parts.from(["tx-1", "placeholder"]);
		Object.defineProperty(parts, 1, {
			get: () => {
				reads += 1;
				return reads === 1 ? "123456" : "999999";
			},
			enumerable: true,
		});
		expect(digests.digest(parts)).toEqual(digests.digest(["tx-1", "123456"]));
		expect(reads).toBe(1);
		reads = 0;
		expect(digests.matchesDigest(parts, digests.digest(["tx-1", "123456"]))).toBe("match");
		expect(reads).toBe(1);
	});

	it("refuses parts that are not strings, in its own words, and a kind it cannot bind to", () => {
		const digests = sealingOver([K1]).digestsFor("email");
		const PARTS = "a digest is made over a list of well-formed strings";
		for (const parts of [[1], ["a", ["b"]], ["a", { b: "c" }], "ab", null]) {
			expect(() => digests.digest(parts as never)).toThrow(new RangeError(PARTS));
			expect(() => digests.matchesDigest(parts as never, digests.digest(["a"]))).toThrow(
				new RangeError(PARTS),
			);
		}
		expect(() => sealingOver([K1]).digestsFor("")).toThrow(RangeError);
	});

	it("refuses, in its own words, parts whose length or a part cannot be read", () => {
		const digests = sealingOver([K1]).digestsFor("email");
		const unreadableLength = new Proxy(["a"], {
			get: (target, key, receiver) => {
				if (key === "length") throw new Error("S3CR3T");
				return Reflect.get(target, key, receiver);
			},
		});
		const unreadablePart = Object.defineProperty(["a", "b"], 1, {
			get: () => {
				throw new Error("S3CR3T");
			},
		});
		for (const parts of [unreadableLength, unreadablePart]) {
			expect(() => digests.digest(parts)).toThrow(
				new RangeError("a digest is made over a list of well-formed strings"),
			);
		}
	});

	it("never descends into a part: one nested past any stack is refused as a part that is not a string", () => {
		const digests = sealingOver([K1]).digestsFor("email");
		let deep: unknown = "x";
		for (let depth = 0; depth < 200_000; depth++) deep = [deep];
		expect(() => digests.digest(["a", deep] as never)).toThrow(
			new RangeError("a digest is made over a list of well-formed strings"),
		);
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

describe("what is sealed: plain JSON-shaped values, copied once", () => {
	const SECRET_TEXT = "S3CR3T-VALUE";
	const STATE_BINDING = { transactionId: "tx-1", kind: "totp", use: "enrollment" } as const;
	/** What every refusal says, whatever was refused: nothing of the value. */
	const NOT_PLAIN =
		"a factor's data, state or response must be a plain JSON object of plain JSON values";

	/** What `run` threw, or `undefined`. */
	const thrownBy = (run: () => unknown): unknown => {
		try {
			run();
		} catch (error) {
			return error;
		}
		return undefined;
	};

	it("refuses, in one fixed text that quotes nothing, anything but a plain JSON object of plain JSON values — a class's instance, an Array subclass and a built-in among them — never sealing part of it", () => {
		const sealing = sealingOver([K1]);
		const cycle: Record<string, unknown> = { secret: SECRET_TEXT };
		cycle.self = cycle;
		class OwnFields {
			readonly secret = SECRET_TEXT;
		}
		class PrototypeGetters {
			get secret(): string {
				return SECRET_TEXT;
			}
		}
		class Tagged {
			readonly secret = SECRET_TEXT;
			get [Symbol.toStringTag](): string {
				return "Tagged";
			}
		}
		class Listish extends Array<string> {}
		const subclassWithExtra = Listish.from([SECRET_TEXT]) as Listish & { extra?: string };
		subclassWithExtra.extra = SECRET_TEXT;
		const listWithExtra = [SECRET_TEXT] as string[] & { extra?: string };
		listWithExtra.extra = SECRET_TEXT;
		const mapTaggedObject = new Map([["secret", SECRET_TEXT]]);
		Object.defineProperty(mapTaggedObject, Symbol.toStringTag, { value: "Object" });
		const hidden = (target: object, key: PropertyKey, value: unknown) =>
			Object.defineProperty(target, key, { value, enumerable: false });
		// Each node holds the one before. Every thousandth is listed in order, so the copy
		// meets each shared node once and never goes past a thousand deep, while JSON
		// writes each listed node whole, deeper than its stack.
		const chain: Record<string, unknown>[] = [];
		for (let index = 0; index < 20_000; index++) chain.push({ n: chain[index - 1] ?? null });
		const everyThousandth = chain.filter((_, index) => index % 1000 === 999);
		let deep: Record<string, unknown> = { secret: SECRET_TEXT };
		for (let depth = 0; depth < 200_000; depth++) deep = { deep };
		for (const [label, value] of [
			["a Date", new Date(0)],
			["a toJSON that answers a string", { secret: SECRET_TEXT, toJSON: () => SECRET_TEXT }],
			["a Map", new Map([["secret", SECRET_TEXT]])],
			["a Map tagged Object", { map: mapTaggedObject }],
			["a Proxy over a RegExp", { pattern: new Proxy(/S3CR3T/, {}) }],
			["a Proxy over a Number", { n: new Proxy(new Number(1), {}) }],
			["a class's instance with its own fields", new OwnFields()],
			["a class's instance with prototype getters", new PrototypeGetters()],
			["a class's instance nested", { nested: new PrototypeGetters() }],
			["a class with a tag of its own", { tagged: new Tagged() }],
			["an object over another prototype", { nested: Object.create({ secret: SECRET_TEXT }) }],
			["an Array subclass", { list: Listish.from([SECRET_TEXT]) }],
			["an Array subclass with a field of its own", { list: subclassWithExtra }],
			["a list with a field of its own", { list: listWithExtra }],
			[
				"a toJSON JSON would call, hidden from the keys",
				hidden({ secret: "s" }, "toJSON", () => ({})),
			],
			["a field hidden from the keys", hidden({ secret: "s" }, "extra", SECRET_TEXT)],
			["a field keyed by a symbol", { secret: "s", [Symbol("extra")]: SECRET_TEXT }],
			["a list with a hidden field", { list: hidden([SECRET_TEXT], "extra", SECRET_TEXT) }],
			[
				"a list with a field keyed by a symbol",
				{ list: hidden(["s"], Symbol("extra"), SECRET_TEXT) },
			],
			["a BigInt inside", { secret: SECRET_TEXT, n: 1n }],
			["a cycle", cycle],
			["a Map inside", { secret: SECRET_TEXT, m: new Map([["a", 1]]) }],
			["a Set inside", { secret: SECRET_TEXT, s: new Set([SECRET_TEXT]) }],
			["a Date inside", { secret: SECRET_TEXT, at: new Date(0) }],
			["NaN inside", { secret: SECRET_TEXT, n: Number.NaN }],
			["Infinity inside", { secret: SECRET_TEXT, n: Number.POSITIVE_INFINITY }],
			["a function inside", { secret: SECRET_TEXT, f: () => SECRET_TEXT }],
			["undefined in a list", { secret: SECRET_TEXT, list: [1, undefined] }],
			// biome-ignore lint/suspicious/noSparseArray: a hole is what this case is
			["a hole in a list", { secret: SECRET_TEXT, list: [1, , 2] }],
			["a list at the top", [SECRET_TEXT]],
			["nesting past any stack", deep],
			["nesting JSON cannot write, each level shared", { nodes: everyThousandth }],
			["-0 inside", { secret: SECRET_TEXT, n: -0 }],
			["-0 in a list", { list: [0, -0] }],
			[
				"a getter that throws",
				{
					get secret(): string {
						throw new Error(SECRET_TEXT);
					},
				},
			],
		] as const) {
			for (const run of [
				() => sealing.sealFactorData(RECORD, value as never),
				() => sealing.sealState(STATE_BINDING, value as never),
				() => copyFactorValue(value),
			]) {
				const thrown = thrownBy(run);
				expect(thrown, label).toBeInstanceOf(RangeError);
				expect((thrown as Error).message, label).toBe(NOT_PLAIN);
			}
		}
	});

	it("copies a plain value's every field once, an own getter's among them, into a frozen plain copy, and seals that copy", () => {
		const reads = { secret: 0, shared: 0, index: 0 };
		/** Counts its reads; answers "first" to the first and the secret to any later one. */
		const counted = (key: keyof typeof reads) => () => {
			reads[key] += 1;
			return reads[key] === 1 ? "first" : SECRET_TEXT;
		};
		const shared = Object.defineProperty({}, "value", { get: counted("shared"), enumerable: true });
		const list: unknown[] = ["a", "b"];
		Object.defineProperty(list, 1, { get: counted("index"), enumerable: true });
		const value = Object.defineProperty(
			{ lastUsedStep: 42, list, one: shared, two: shared },
			"secret",
			{ get: counted("secret"), enumerable: true },
		);

		const copy = copyFactorValue(value);

		expect(copy).toEqual({
			lastUsedStep: 42,
			list: ["a", "first"],
			one: { value: "first" },
			two: { value: "first" },
			secret: "first",
		});
		// Each field read once, an object two fields share among them: it is one copy.
		expect(reads).toEqual({ secret: 1, shared: 1, index: 1 });
		expect(copy.one).toBe(copy.two);
		for (const part of [copy, copy.list, copy.one]) {
			expect(Object.isFrozen(part)).toBe(true);
		}
		expect(Object.getPrototypeOf(copy)).toBe(Object.prototype);
		expect(Object.getPrototypeOf(copy.list)).toBe(Array.prototype);

		const sealing = sealingOver([K1]);
		expect(sealing.openFactorData(RECORD, sealing.sealFactorData(RECORD, copy))).toEqual({
			state: "ok",
			value: copy,
			keyId: "k1",
		});
		expect(
			sealing.openState(STATE_BINDING, sealing.sealState(STATE_BINDING, { state: copy })),
		).toEqual({ state: "ok", value: { state: copy }, keyId: "k1" });
	});

	it("copies a Proxy over a plain object or list as the plain value it shows, each field read once", () => {
		const gets: string[] = [];
		const traced = <T extends object>(target: T): T =>
			new Proxy(target, {
				get(on, key, receiver) {
					if (typeof key === "string") gets.push(key);
					return Reflect.get(on, key, receiver);
				},
			});
		const value = traced({ secret: "s", list: traced(["a", "b"]) });
		expect(copyFactorValue(value)).toEqual({ secret: "s", list: ["a", "b"] });
		expect(gets.filter((key) => key !== "length").sort()).toEqual(["0", "1", "list", "secret"]);
		expect(gets.filter((key) => key === "length")).toEqual(["length"]);
	});

	it("keeps an own __proto__ key as the field it is, through the seal and back", () => {
		const value = JSON.parse('{"__proto__":{"polluted":true},"b":2}') as Record<string, unknown>;
		const copy = copyFactorValue(value);
		expect(Object.hasOwn(copy, "__proto__")).toBe(true);
		expect(Object.getPrototypeOf(copy)).toBe(Object.prototype);
		const sealing = sealingOver([K1]);
		const opened = sealing.openFactorData(RECORD, sealing.sealFactorData(RECORD, copy));
		expect(opened.state).toBe("ok");
		const reopened = (opened as { value: Record<string, unknown> }).value;
		expect(Object.hasOwn(reopened, "__proto__")).toBe(true);
		expect(JSON.stringify(reopened)).toBe('{"__proto__":{"polluted":true},"b":2}');
		expect(({} as Record<string, unknown>).polluted).toBeUndefined();
	});

	it("copies a diamond — one object reached by two paths — once, and seals it at both", () => {
		let reads = 0;
		const leaf = Object.defineProperty({}, "n", {
			get: () => {
				reads += 1;
				return 1;
			},
			enumerable: true,
		});
		const value = { left: { leaf }, right: { leaf } };
		const copy = copyFactorValue(value);
		expect(reads).toBe(1);
		const sealing = sealingOver([K1]);
		expect(sealing.openFactorData(RECORD, sealing.sealFactorData(RECORD, copy))).toEqual({
			state: "ok",
			value: { left: { leaf: { n: 1 } }, right: { leaf: { n: 1 } } },
			keyId: "k1",
		});
	});

	it("seals an object without a prototype as the plain object it is", () => {
		const sealing = sealingOver([K1]);
		const value = Object.assign(Object.create(null) as Record<string, unknown>, {
			lastUsedStep: 7,
			nested: Object.assign(Object.create(null) as Record<string, unknown>, { a: [1] }),
		});
		expect(sealing.openFactorData(RECORD, sealing.sealFactorData(RECORD, value))).toEqual({
			state: "ok",
			value: { lastUsedStep: 7, nested: { a: [1] } },
			keyId: "k1",
		});
	});

	it("leaves out, as absent, a field an own getter answers undefined for, and one a setter alone holds", () => {
		const value = Object.defineProperties(
			{ kept: 1 },
			{
				answersUndefined: { get: () => undefined, enumerable: true },
				setterOnly: { set: () => {}, enumerable: true },
			},
		);
		expect(copyFactorValue(value)).toEqual({ kept: 1 });
		const sealing = sealingOver([K1]);
		expect(sealing.openFactorData(RECORD, sealing.sealFactorData(RECORD, value))).toEqual({
			state: "ok",
			value: { kept: 1 },
			keyId: "k1",
		});
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
