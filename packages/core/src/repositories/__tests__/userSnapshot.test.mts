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
 * `readUserSnapshot` through core's public entry: a login's one read of the
 * `User` a repository answers, which a route reads the subject and the
 * claims from instead of the `User` itself.
 */

import { describe, expect, expectTypeOf, it } from "vitest";
import { readUserSnapshot, type User, type UserSnapshotReading } from "#/index.mjs";

/** A `User` whose every field is a prototype getter, counting its reads by name. */
function countingUser(fields: Record<string, unknown>): { user: User; reads: Map<string, number> } {
	const reads = new Map<string, number>();
	class Entity {}
	for (const [name, value] of Object.entries(fields)) {
		Object.defineProperty(Entity.prototype, name, {
			get() {
				reads.set(name, (reads.get(name) ?? 0) + 1);
				return value;
			},
			configurable: true,
		});
	}
	return { user: new Entity() as unknown as User, reads };
}

describe("readUserSnapshot, from core's public entry", () => {
	it("reads each field User declares once into a frozen plain snapshot that shares nothing with the User", () => {
		const groups = ["staff"];
		const { user, reads } = countingUser({
			id: "u-1",
			username: "alice",
			email: "alice@example.com",
			emailVerified: true,
			name: "Alice",
			picture: "https://example.com/a.png",
			groups,
			mfaEnrolled: false,
			locale: "en",
		});

		const reading = readUserSnapshot(user);

		expect(reading).toStrictEqual({
			ok: true,
			snapshot: {
				id: "u-1",
				username: "alice",
				email: "alice@example.com",
				emailVerified: true,
				name: "Alice",
				picture: "https://example.com/a.png",
				groups: ["staff"],
				mfaEnrolled: false,
			},
		});
		expect(Object.fromEntries(reads)).toStrictEqual({
			id: 1,
			username: 1,
			email: 1,
			emailVerified: 1,
			name: 1,
			picture: 1,
			groups: 1,
			mfaEnrolled: 1,
		});
		if (!reading.ok) return;
		expect(Object.getPrototypeOf(reading.snapshot)).toBe(Object.prototype);
		expect(Object.isFrozen(reading.snapshot)).toBe(true);
		expect(Object.isFrozen(reading.snapshot.groups)).toBe(true);
		expect(reading.snapshot.groups).not.toBe(groups);
	});

	it("answers the snapshot's id as a string", () => {
		expectTypeOf<
			Extract<UserSnapshotReading, { ok: true }>["snapshot"]["id"]
		>().toEqualTypeOf<string>();
	});

	it.each<[string, unknown, UserSnapshotReading]>([
		["a User that is not an object", "u-1", { ok: false, refused: "not_an_object" }],
		[
			"an id that is not a non-empty string",
			{ id: "", username: "a" },
			{ ok: false, refused: "id" },
		],
		[
			"a declared field holding what is not plain data",
			{ id: "u-1", username: "a", mfaEnrolled: new Date(0) },
			{ ok: false, refused: "not_plain_data", field: "mfaEnrolled" },
		],
	])("refuses %s, as a verdict", (_label, user, refusal) => {
		expect(readUserSnapshot(user)).toStrictEqual(refusal);
	});
});
