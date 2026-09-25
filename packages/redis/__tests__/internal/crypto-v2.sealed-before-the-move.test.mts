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

// Every federation grant credential at rest was sealed by the `v2` envelope
// code as it stood before that code moved into core's `sealing/` leaf. A
// deployment upgrades with those records in Redis, and during a rolling
// upgrade a replica still on the old code reads what an upgraded one seals.
//
// So both directions are pinned: the envelopes in the fixture were sealed by
// `sealCredential` in `src/internal/crypto.mts` at d3d9c8f2 (the ciphertext is
// fixed, since the IV is random and cannot be reproduced) and must open with
// the code as it is now; and what the code seals now must open with the
// reader as it was then, restated below from the format — the header, the
// key ID and the record's own bytes, each after the first length-prefixed.

import { createDecipheriv } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
	type FederationGrantKey,
	openSealedCredential,
	sealCredential,
} from "#/internal/crypto.mjs";
import {
	credentialAad,
	decodeCredentials,
	type FederationGrantCredentialBinding,
} from "#/internal/federation-grant-codec.mjs";

interface FixtureCase {
	readonly name: string;
	readonly sealedWith: string;
	readonly binding?: FederationGrantCredentialBinding;
	/** base64 */
	readonly record: string;
	readonly plaintext: string;
	readonly envelope: string;
}

interface Fixture {
	readonly sealedAt: string;
	readonly ring: ReadonlyArray<{ readonly id: string; readonly key: string }>;
	readonly cases: readonly FixtureCase[];
}

const fixture: Fixture = JSON.parse(
	readFileSync(
		new URL("./fixtures/v2-envelopes.sealed-before-the-move.json", import.meta.url),
		"utf8",
	),
);

const RING: readonly FederationGrantKey[] = fixture.ring.map((entry) => ({
	id: entry.id,
	key: Buffer.from(entry.key, "base64"),
}));

const recordOf = (entry: FixtureCase): Buffer => Buffer.from(entry.record, "base64");

/** The reader as it was before the move: the `v2` format, restated from nothing but node:crypto. */
const openAsBeforeTheMove = (
	envelope: string,
	ring: readonly FederationGrantKey[],
	record: Buffer,
): string => {
	const [version, keyId, iv, ciphertext, tag, ...rest] = envelope.split(".");
	if (version !== "v2" || tag === undefined || rest.length > 0) {
		throw new Error("not a v2 envelope");
	}
	const kid = Buffer.from(keyId as string, "base64url");
	const entry = ring.find((candidate) => candidate.id === kid.toString("utf8"));
	if (entry === undefined) throw new Error("key not in the ring");
	const prefix = (bytes: Buffer): Buffer => {
		const length = Buffer.alloc(4);
		length.writeUInt32BE(bytes.length);
		return length;
	};
	const decipher = createDecipheriv(
		"aes-256-gcm",
		entry.key,
		Buffer.from(iv as string, "base64url"),
	);
	decipher.setAAD(
		Buffer.concat([
			Buffer.from("o3co:redis:v2\0", "ascii"),
			prefix(kid),
			kid,
			prefix(record),
			record,
		]),
	);
	decipher.setAuthTag(Buffer.from(tag, "base64url"));
	return Buffer.concat([
		decipher.update(Buffer.from(ciphertext as string, "base64url")),
		decipher.final(),
	]).toString("utf8");
};

describe("v2 envelopes sealed before the envelope moved to core", () => {
	it("holds a case for each shape a deployment has at rest", () => {
		// A fixture that lost its cases would pass every assertion below.
		expect(fixture.sealedAt).toBe("d3d9c8f212c096b4c1802baf28044f19165678c9");
		expect(fixture.cases).toHaveLength(5);
		expect(new Set(fixture.cases.map((entry) => entry.sealedWith))).toEqual(
			new Set(fixture.ring.map((entry) => entry.id)),
		);
	});

	it.each(fixture.cases.map((entry) => [entry.name, entry] as const))(
		"opens: %s",
		(_name, entry) => {
			expect(openSealedCredential(entry.envelope, RING, recordOf(entry))).toStrictEqual({
				state: "ok",
				value: entry.plaintext,
				keyId: entry.sealedWith,
			});
		},
	);

	it("opens a grant's credential through the store's own record binding, and decodes it", () => {
		const entry = fixture.cases.find((candidate) => candidate.binding !== undefined);
		if (entry?.binding === undefined) throw new Error("the fixture has no grant case");
		// The store rebuilds the authenticated data from the record it read; the
		// fixture's bytes are what that rebuild has to produce.
		const record = credentialAad(entry.binding);
		expect(record.equals(recordOf(entry))).toBe(true);
		const opened = openSealedCredential(entry.envelope, RING, record);
		expect(opened.state).toBe("ok");
		expect(opened.state === "ok" && decodeCredentials(opened.value)).toStrictEqual({
			refreshToken: "1//0gRefreshTokenExample-abc_DEF",
			accessToken: {
				value: "ya29.a0AccessTokenExample",
				tokenType: "Bearer",
				obtainedAt: new Date("2026-09-20T12:00:00.000Z"),
				issuedLifetime: 3599,
				scopes: ["openid", "email"],
			},
		});
	});

	it("still tells a dropped key and another record apart on those envelopes", () => {
		const entry = fixture.cases[0] as FixtureCase;
		const withoutItsKey = RING.filter((candidate) => candidate.id !== entry.sealedWith);
		expect(openSealedCredential(entry.envelope, withoutItsKey, recordOf(entry))).toStrictEqual({
			state: "key_unavailable",
			keyId: entry.sealedWith,
		});
		expect(
			openSealedCredential(entry.envelope, RING, Buffer.from("another record", "utf8")),
		).toStrictEqual({ state: "unreadable" });
	});
});

describe("what is sealed now opens with the reader as it was before the move", () => {
	it.each(fixture.cases.map((entry) => [entry.name, entry] as const))(
		"a value like: %s",
		(_name, entry) => {
			const ring = [
				RING.find((candidate) => candidate.id === entry.sealedWith) as FederationGrantKey,
			];
			const sealed = sealCredential(entry.plaintext, ring, recordOf(entry));
			expect(openAsBeforeTheMove(sealed, RING, recordOf(entry))).toBe(entry.plaintext);
		},
	);

	it("and the restated reader is the one the fixture's envelopes were sealed for", () => {
		// Were the restatement wrong, the direction above would prove nothing.
		for (const entry of fixture.cases) {
			expect(openAsBeforeTheMove(entry.envelope, RING, recordOf(entry)), entry.name).toBe(
				entry.plaintext,
			);
		}
	});
});
