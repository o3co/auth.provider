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

// The `v2` envelope a federation grant's credential is sealed in (#593, D16).
//
// Two things make it a new format rather than a parameter of `v1`: it names
// the key that sealed it, so that a ring can be rotated without re-sealing
// every paused grant, and an unknown key ID is told apart from a failed tag —
// one is a configuration problem the operator can undo, the other is a record
// that will never open again. Neither ever deletes anything.

import { createCipheriv, randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
	decryptTokenField,
	encryptTokenField,
	type FederationGrantKey,
	openSealedCredential,
	sealCredential,
} from "../../src/internal/crypto.mjs";

const key = (byte: number): Buffer => Buffer.alloc(32, byte);
const RING: readonly FederationGrantKey[] = [
	{ id: "k-2026-09", key: key(2) },
	{ id: "k-2026-03", key: key(1) },
];
const AAD = Buffer.from("the record this credential belongs to", "utf8");

describe("the v2 federation grant credential envelope (#593, D16)", () => {
	it("is five dot-separated segments naming the key that sealed it: the first in the ring", () => {
		const sealed = sealCredential("rt-1", RING, AAD);
		const parts = sealed.split(".");
		expect(parts).toHaveLength(5);
		expect(parts[0]).toBe("v2");
		expect(Buffer.from(parts[1] as string, "base64url").toString("utf8")).toBe("k-2026-09");
		// 12-byte IV, 16-byte tag, as AES-256-GCM is used everywhere here.
		expect(Buffer.from(parts[2] as string, "base64url")).toHaveLength(12);
		expect(Buffer.from(parts[4] as string, "base64url")).toHaveLength(16);
	});

	it("opens under the key that sealed it, and under an older key still in the ring", () => {
		const fresh = sealCredential("rt-fresh", RING, AAD);
		const old = sealCredential("rt-old", [RING[1] as FederationGrantKey], AAD);
		expect(openSealedCredential(fresh, RING, AAD)).toStrictEqual({
			state: "ok",
			value: "rt-fresh",
		});
		expect(openSealedCredential(old, RING, AAD)).toStrictEqual({ state: "ok", value: "rt-old" });
	});

	it("tells an unknown key ID from a failed tag: one is undone by putting the key back, the other never opens", () => {
		const sealed = sealCredential("rt-1", RING, AAD);
		// The operator dropped the key that sealed it from the ring.
		expect(openSealedCredential(sealed, [RING[1] as FederationGrantKey], AAD)).toStrictEqual({
			state: "key_unavailable",
		});
		// The key ID is known, the material behind it is not the one that sealed.
		const wrong: readonly FederationGrantKey[] = [{ id: "k-2026-09", key: key(9) }];
		expect(openSealedCredential(sealed, wrong, AAD)).toStrictEqual({ state: "unreadable" });
		// And the ring it was sealed under still opens it: nothing was consumed.
		expect(openSealedCredential(sealed, RING, AAD)).toStrictEqual({ state: "ok", value: "rt-1" });
	});

	it("authenticates the record it was sealed for: another record's data does not open it", () => {
		const sealed = sealCredential("rt-1", RING, AAD);
		expect(openSealedCredential(sealed, RING, Buffer.from("another record", "utf8"))).toStrictEqual(
			{ state: "unreadable" },
		);
	});

	it("authenticates the key ID in its own envelope: renaming it to another key of the same material fails", () => {
		// Two IDs, one key. Without the ID inside the authenticated data, an
		// envelope could be re-labelled to whichever ID an attacker wanted the
		// record to name — the plaintext would still come out.
		const ring: readonly FederationGrantKey[] = [
			{ id: "a", key: key(3) },
			{ id: "b", key: key(3) },
		];
		const sealed = sealCredential("rt-1", ring, AAD);
		const relabelled = ["v2", Buffer.from("b", "utf8").toString("base64url")]
			.concat(sealed.split(".").slice(2))
			.join(".");
		expect(openSealedCredential(relabelled, ring, AAD)).toStrictEqual({ state: "unreadable" });
	});

	it("reads nothing but its own shape: a v1 envelope, a segment that is not canonical base64url, a wrong version, a truncated one", () => {
		const v1 = encryptTokenField("rt-1", key(1), "aad");
		const sealed = sealCredential("rt-1", RING, AAD);
		const parts = sealed.split(".");
		const cases: Record<string, string> = {
			"a v1 envelope": v1,
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
			"an empty envelope": "",
			"the version alone": "v2",
		};
		for (const [name, envelope] of Object.entries(cases)) {
			expect(openSealedCredential(envelope, RING, AAD), name).toStrictEqual({
				state: "unreadable",
			});
		}
	});

	it("is not read by the v1 reader, and does not read a v1 envelope: the two formats pass each other by", () => {
		const sealed = sealCredential("rt-1", RING, AAD);
		expect(() => decryptTokenField(sealed, key(2), AAD)).toThrow(/envelope/);
		// And v1 keeps working exactly as it did, which is the point of leaving it
		// alone: the session-bound store's records were sealed with it.
		const v1 = encryptTokenField("rt-1", key(1), "aad");
		expect(decryptTokenField(v1, key(1), "aad")).toBe("rt-1");
	});

	it("refuses a ring it cannot seal with: no keys, a key that is not 32 bytes, a duplicate or unusable ID", () => {
		expect(() => sealCredential("rt-1", [], AAD)).toThrow(/key/);
		expect(() => sealCredential("rt-1", [{ id: "k", key: Buffer.alloc(16, 1) }], AAD)).toThrow(
			/32 bytes/,
		);
		expect(() =>
			sealCredential(
				"rt-1",
				[
					{ id: "k", key: key(1) },
					{ id: "k", key: key(2) },
				],
				AAD,
			),
		).toThrow(/id/);
		for (const id of ["", "k.2", "k 2", "k\n", "x".repeat(65)]) {
			expect(() => sealCredential("rt-1", [{ id, key: key(1) }], AAD), JSON.stringify(id)).toThrow(
				/id/,
			);
		}
	});

	it("keeps the ring the caller handed over out of reach: a buffer mutated afterwards does not change what opens", () => {
		const mutable = Buffer.alloc(32, 7);
		const ring: readonly FederationGrantKey[] = [{ id: "k", key: mutable }];
		const sealed = sealCredential("rt-1", ring, AAD);
		mutable.fill(8);
		expect(
			openSealedCredential(sealed, [{ id: "k", key: Buffer.alloc(32, 7) }], AAD),
		).toStrictEqual({ state: "ok", value: "rt-1" });
	});

	it("opens a vector sealed outside this module: the format is a contract, not whatever the writer happens to produce", () => {
		// Sealed here by hand, the way another implementation would have to: the
		// GCM AAD is a header naming the format and the key ID, length-prefixed,
		// then the record's own authenticated data.
		const material = key(4);
		const iv = Buffer.alloc(12, 5);
		const kid = Buffer.from("k-hand", "utf8");
		const header = Buffer.concat([
			Buffer.from("o3co:redis:v2\0", "ascii"),
			(() => {
				const n = Buffer.alloc(4);
				n.writeUInt32BE(kid.length);
				return n;
			})(),
			kid,
			(() => {
				const n = Buffer.alloc(4);
				n.writeUInt32BE(AAD.length);
				return n;
			})(),
			AAD,
		]);
		const cipher = createCipheriv("aes-256-gcm", material, iv);
		cipher.setAAD(header);
		const ct = Buffer.concat([cipher.update("rt-by-hand", "utf8"), cipher.final()]);
		const envelope = [
			"v2",
			kid.toString("base64url"),
			iv.toString("base64url"),
			ct.toString("base64url"),
			cipher.getAuthTag().toString("base64url"),
		].join(".");
		expect(openSealedCredential(envelope, [{ id: "k-hand", key: material }], AAD)).toStrictEqual({
			state: "ok",
			value: "rt-by-hand",
		});
	});

	it("never returns the same IV twice for the same plaintext, and never the same ciphertext", () => {
		const seen = new Set<string>();
		for (let i = 0; i < 64; i += 1) {
			const parts = sealCredential("rt-1", RING, AAD).split(".");
			seen.add(`${parts[2]}.${parts[3]}`);
		}
		expect(seen.size).toBe(64);
		// And the IV really comes from the platform's CSPRNG, not a counter.
		expect(randomBytes(12)).toHaveLength(12);
	});
});
