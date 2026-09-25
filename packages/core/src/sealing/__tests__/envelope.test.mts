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

// The `v2` key-ring envelope a value is sealed in at rest.
//
// Two things make it a format of its own rather than a key and a cipher: it
// names the key that sealed it, so that a ring can be rotated without
// re-sealing every value at rest, and an unknown key ID is told apart from a
// failed tag — one is a configuration problem the operator can undo, the other
// is a value that will never open again. Neither ever deletes anything.

import { createCipheriv } from "node:crypto";
import { describe, expect, it } from "vitest";
import { openWithKeyRing, type SealBinding, sealWithKeyRing } from "#/sealing/envelope.mjs";
import type { SealingKey, SealingKeyRing } from "#/sealing/keyRing.mjs";

const key = (byte: number): Buffer => Buffer.alloc(32, byte);
const RING: SealingKeyRing = [
	{ id: "k-2026-09", key: key(2) },
	{ id: "k-2026-03", key: key(1) },
];
const BINDING: SealBinding = {
	purpose: "o3co:test:value",
	record: Buffer.from("the record this value belongs to", "utf8"),
};

/** What `run` threw: its exact class and its message. */
const refusal = (run: () => unknown): { class: unknown; message: string } => {
	try {
		run();
	} catch (err) {
		return { class: (err as Error).constructor, message: (err as Error).message };
	}
	throw new Error("expected a refusal");
};

const u32 = (value: number): Buffer => {
	const out = Buffer.alloc(4);
	out.writeUInt32BE(value);
	return out;
};

describe("the v2 key-ring envelope", () => {
	it("is five dot-separated segments naming the key that sealed it: the first in the ring", () => {
		const sealed = sealWithKeyRing("rt-1", RING, BINDING);
		const parts = sealed.split(".");
		expect(parts).toHaveLength(5);
		expect(parts[0]).toBe("v2");
		expect(Buffer.from(parts[1] as string, "base64url").toString("utf8")).toBe("k-2026-09");
		// 12-byte IV, 16-byte tag: AES-256-GCM.
		expect(Buffer.from(parts[2] as string, "base64url")).toHaveLength(12);
		expect(Buffer.from(parts[4] as string, "base64url")).toHaveLength(16);
	});

	it("opens under the key that sealed it, and under an older key still in the ring, and says which", () => {
		// Which key opened a value is what a caller re-seals by: a value opened
		// under a key that is no longer first was sealed with a retired one.
		const fresh = sealWithKeyRing("rt-fresh", RING, BINDING);
		const old = sealWithKeyRing("rt-old", [RING[1] as SealingKey], BINDING);
		expect(openWithKeyRing(fresh, RING, BINDING)).toStrictEqual({
			state: "ok",
			value: "rt-fresh",
			keyId: "k-2026-09",
		});
		expect(openWithKeyRing(old, RING, BINDING)).toStrictEqual({
			state: "ok",
			value: "rt-old",
			keyId: "k-2026-03",
		});
	});

	it("tells an unknown key ID from a failed tag: one is undone by putting the key back, the other never opens", () => {
		const sealed = sealWithKeyRing("rt-1", RING, BINDING);
		// The operator dropped the key that sealed it from the ring; the answer
		// names the key to put back.
		expect(openWithKeyRing(sealed, [RING[1] as SealingKey], BINDING)).toStrictEqual({
			state: "key_unavailable",
			keyId: "k-2026-09",
		});
		// The key ID is known, the material behind it is not the one that sealed.
		const wrong: SealingKeyRing = [{ id: "k-2026-09", key: key(9) }];
		expect(openWithKeyRing(sealed, wrong, BINDING)).toStrictEqual({ state: "unreadable" });
		// And the ring it was sealed under still opens it: nothing was consumed.
		expect(openWithKeyRing(sealed, RING, BINDING)).toStrictEqual({
			state: "ok",
			value: "rt-1",
			keyId: "k-2026-09",
		});
	});

	it("authenticates the record it was sealed for: another record's data does not open it", () => {
		const sealed = sealWithKeyRing("rt-1", RING, BINDING);
		expect(
			openWithKeyRing(sealed, RING, { ...BINDING, record: Buffer.from("another record", "utf8") }),
		).toStrictEqual({ state: "unreadable" });
	});

	it("authenticates the purpose it was sealed for: the same record under another purpose does not open it", () => {
		// Two callers sealing under one ring cannot read each other's values,
		// even where the record bytes they bind happen to coincide.
		const sealed = sealWithKeyRing("rt-1", RING, BINDING);
		expect(openWithKeyRing(sealed, RING, { ...BINDING, purpose: "o3co:test:other" })).toStrictEqual(
			{ state: "unreadable" },
		);
	});

	it("authenticates the key ID in its own envelope: renaming it to another key of the same material fails", () => {
		// Two IDs, one key. Without the ID inside the authenticated data, an
		// envelope could be re-labelled to whichever ID an attacker wanted the
		// value to name — the plaintext would still come out.
		const ring: SealingKeyRing = [
			{ id: "a", key: key(3) },
			{ id: "b", key: key(3) },
		];
		const sealed = sealWithKeyRing("rt-1", ring, BINDING);
		const relabelled = ["v2", Buffer.from("b", "utf8").toString("base64url")]
			.concat(sealed.split(".").slice(2))
			.join(".");
		expect(openWithKeyRing(relabelled, ring, BINDING)).toStrictEqual({ state: "unreadable" });
	});

	it("reads nothing but its own shape: a wrong version, a segment that is not canonical base64url, a truncated one", () => {
		const sealed = sealWithKeyRing("rt-1", RING, BINDING);
		const parts = sealed.split(".");
		const cases: Record<string, string> = {
			"a v1 envelope's shape": ["v1", parts[2], parts[3], parts[4]].join("."),
			"a v3 envelope": sealed.replace(/^v2\./, "v3."),
			"four segments": parts.slice(0, 4).join("."),
			"six segments": `${sealed}.x`,
			// `Buffer.from` drops what it cannot decode rather than refusing, so a
			// segment that is not canonical base64url would otherwise be accepted
			// and read as some shorter value.
			"a non-canonical IV": [parts[0], parts[1], `${parts[2]}=`, parts[3], parts[4]].join("."),
			// Standard base64, not base64url: twelve 0xff bytes spell "/" sixteen
			// times there and "_" sixteen times here. Permissive decoding would
			// take it and read the same IV.
			"an IV spelled in standard base64": [
				parts[0],
				parts[1],
				Buffer.alloc(12, 0xff).toString("base64"),
				parts[3],
				parts[4],
			].join("."),
			// A key ID no ring may hold is not a key the operator could put back.
			"a key ID outside the rule": [
				parts[0],
				Buffer.from("k.2", "utf8").toString("base64url"),
				parts[2],
				parts[3],
				parts[4],
			].join("."),
			"an empty envelope": "",
			"the version alone": "v2",
		};
		for (const [name, envelope] of Object.entries(cases)) {
			expect(openWithKeyRing(envelope, RING, BINDING), name).toStrictEqual({
				state: "unreadable",
			});
		}
	});

	it("reads only a 16-byte tag and a 12-byte IV, whatever lengths the platform's GCM would take", () => {
		// Node before 26 accepts a GCM tag of 4 to 16 bytes on decrypt unless
		// told the length, so an envelope whose tag was cut short opened: a
		// forgery would then need to match 32 bits, not 128, and short tags
		// leak the authentication key (Ferguson). Every envelope ever sealed
		// has a 12-byte IV and a 16-byte tag, so nothing else is read.
		const parts = sealWithKeyRing("rt-1", RING, BINDING).split(".");
		const tag = Buffer.from(parts[4] as string, "base64url");
		for (const length of [4, 8, 12]) {
			const truncated = [...parts.slice(0, 4), tag.subarray(0, length).toString("base64url")].join(
				".",
			);
			expect(openWithKeyRing(truncated, RING, BINDING), `a ${length}-byte tag`).toStrictEqual({
				state: "unreadable",
			});
		}
		// A 16-byte IV, sealed by hand under the right key and the right
		// authenticated data: GCM itself would take it.
		const kid = Buffer.from("k-2026-09", "utf8");
		const iv = Buffer.alloc(16, 9);
		const cipher = createCipheriv("aes-256-gcm", key(2), iv);
		cipher.setAAD(
			Buffer.concat([
				Buffer.from("o3co:test:value\0", "ascii"),
				u32(kid.length),
				kid,
				u32(BINDING.record.length),
				BINDING.record,
			]),
		);
		const ct = Buffer.concat([cipher.update("rt-1", "utf8"), cipher.final()]);
		const longIv = [
			"v2",
			kid.toString("base64url"),
			iv.toString("base64url"),
			ct.toString("base64url"),
			cipher.getAuthTag().toString("base64url"),
		].join(".");
		expect(openWithKeyRing(longIv, RING, BINDING), "a 16-byte IV").toStrictEqual({
			state: "unreadable",
		});
	});

	it("refuses a ring it cannot seal with, as a RangeError: no keys, a key that is not 32 bytes, a duplicate or unusable ID", () => {
		// A ring is a setting, and a setting that cannot be used is refused as a
		// RangeError naming what is wrong with it. Handed a ring directly, the
		// envelope calls it the sealing key ring; a caller that read it from its
		// configuration checks it first under its own name (keyRing.test.mts).
		expect(refusal(() => sealWithKeyRing("rt-1", [], BINDING))).toStrictEqual({
			class: RangeError,
			message: "sealing key ring has no encryption key to seal with",
		});
		expect(
			refusal(() => sealWithKeyRing("rt-1", [{ id: "k", key: Buffer.alloc(16, 1) }], BINDING)),
		).toStrictEqual({
			class: RangeError,
			message: "sealing key ring has an encryption key at index 0 that is not a Buffer of 32 bytes",
		});
		const duplicate: SealingKeyRing = [
			{ id: "k", key: key(1) },
			{ id: "k", key: key(2) },
		];
		expect(refusal(() => sealWithKeyRing("rt-1", duplicate, BINDING))).toStrictEqual({
			class: RangeError,
			message: "sealing key ring has a duplicate encryption key id at index 1",
		});
		for (const id of ["", "k.2", "k 2", "k\n", "x".repeat(65)]) {
			expect(
				refusal(() => sealWithKeyRing("rt-1", [{ id, key: key(1) }], BINDING)),
				JSON.stringify(id),
			).toStrictEqual({
				class: RangeError,
				message:
					"sealing key ring has an encryption key id at index 0 that does not match ^[A-Za-z0-9_-]{1,64}$",
			});
		}
	});

	it("refuses a key that is not a Buffer, however long: a 32-character string would be used as its UTF-8 bytes", () => {
		const text = "k".repeat(32);
		expect(
			refusal(() =>
				sealWithKeyRing("rt-1", [{ id: "k", key: text as unknown as Buffer }], BINDING),
			),
		).toStrictEqual({
			class: RangeError,
			message: "sealing key ring has an encryption key at index 0 that is not a Buffer of 32 bytes",
		});
	});

	it("refuses a record whose length a 32-bit prefix cannot hold, as a RangeError", () => {
		// Four GiB is not allocated here: the record reports the length it would have.
		const record = Object.defineProperty(Buffer.alloc(0), "length", { value: 2 ** 32 });
		expect(refusal(() => sealWithKeyRing("rt-1", RING, { ...BINDING, record }))).toStrictEqual({
			class: RangeError,
			message: "sealing record is longer than a 32-bit length prefix can state",
		});
	});

	it("refuses to open with a ring that could not have sealed: a malformed ring is a configuration fault, not an unreadable value", () => {
		const sealed = sealWithKeyRing("rt-1", RING, BINDING);
		expect(
			refusal(() => openWithKeyRing(sealed, [...RING, { id: "k-2026-09", key: key(7) }], BINDING)),
		).toStrictEqual({
			class: RangeError,
			message: "sealing key ring has a duplicate encryption key id at index 2",
		});
		expect(
			refusal(() => openWithKeyRing(sealed, [{ id: "k", key: Buffer.alloc(31, 1) }], BINDING)),
		).toStrictEqual({
			class: RangeError,
			message: "sealing key ring has an encryption key at index 0 that is not a Buffer of 32 bytes",
		});
		expect(
			refusal(() => openWithKeyRing(sealed, [{ id: "k.2", key: key(1) }], BINDING)),
		).toStrictEqual({
			class: RangeError,
			message:
				"sealing key ring has an encryption key id at index 0 that does not match ^[A-Za-z0-9_-]{1,64}$",
		});
	});

	it("refuses a purpose that is not 1 to 64 printable ASCII characters, on both sides", () => {
		// The purpose is written into the authenticated data followed by a NUL,
		// so no purpose may hold one: "a" and "a\0…" would otherwise be two
		// purposes whose headers one key ID could make identical.
		const sealed = sealWithKeyRing("rt-1", RING, BINDING);
		for (const purpose of ["", "with space", "nul\0inside", "café", "x".repeat(65), "tab\t"]) {
			const binding = { ...BINDING, purpose };
			expect(() => sealWithKeyRing("rt-1", RING, binding), JSON.stringify(purpose)).toThrow(
				RangeError,
			);
			expect(() => openWithKeyRing(sealed, RING, binding), JSON.stringify(purpose)).toThrow(
				RangeError,
			);
		}
		expect(() =>
			sealWithKeyRing("rt-1", RING, { ...BINDING, purpose: "x".repeat(64) }),
		).not.toThrow();
	});

	it("opens a vector sealed outside this module: the format is a contract, not whatever the writer happens to produce", () => {
		// Sealed here by hand, the way another implementation would have to: the
		// GCM AAD is the purpose and a NUL, then the key ID and the record's own
		// bytes, each after a 32-bit big-endian length.
		const material = key(4);
		const iv = Buffer.alloc(12, 5);
		const kid = Buffer.from("k-hand", "utf8");
		const aad = Buffer.concat([
			Buffer.from("o3co:test:value\0", "ascii"),
			u32(kid.length),
			kid,
			u32(BINDING.record.length),
			BINDING.record,
		]);
		const cipher = createCipheriv("aes-256-gcm", material, iv);
		cipher.setAAD(aad);
		const ct = Buffer.concat([cipher.update("rt-by-hand", "utf8"), cipher.final()]);
		const envelope = [
			"v2",
			kid.toString("base64url"),
			iv.toString("base64url"),
			ct.toString("base64url"),
			cipher.getAuthTag().toString("base64url"),
		].join(".");
		expect(openWithKeyRing(envelope, [{ id: "k-hand", key: material }], BINDING)).toStrictEqual({
			state: "ok",
			value: "rt-by-hand",
			keyId: "k-hand",
		});
	});

	it("round-trips the empty value, multi-byte UTF-8 and binary record bytes", () => {
		for (const [plaintext, record] of [
			["", Buffer.alloc(0)],
			["トークン \u{1F511} ü", Buffer.from([0, 1, 2, 0xfe, 0xff, 0])],
		] as const) {
			const binding = { ...BINDING, record };
			expect(
				openWithKeyRing(sealWithKeyRing(plaintext, RING, binding), RING, binding),
			).toStrictEqual({ state: "ok", value: plaintext, keyId: "k-2026-09" });
		}
	});

	it("never uses the same IV twice under one key", () => {
		// GCM under a repeated IV leaks the XOR of two plaintexts and the
		// authentication key, so the IVs alone are what must differ.
		const ivs = new Set<string>();
		for (let i = 0; i < 64; i += 1) {
			ivs.add(sealWithKeyRing("rt-1", RING, BINDING).split(".")[2] as string);
		}
		expect(ivs.size).toBe(64);
	});
});
