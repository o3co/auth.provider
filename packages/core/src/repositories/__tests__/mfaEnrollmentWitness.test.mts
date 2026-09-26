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
 * The MFA enrollment witness (the MFA ADR's D12): a fact outside the factor
 * store that the subject enrolled, so that losing the factor store — a Redis
 * restarted without persistence, an eviction, a Store restored from an old
 * backup — is not read as "this user never enrolled", which would let
 * whoever holds the password bind their own authenticator.
 *
 * The Store answers it on `authenticate` as `User.mfaEnrolled`, and may be
 * told it through an optional `UserRepository` capability,
 * `markMfaEnrolled`, which a guard detects by method presence. A repository
 * without the capability, and a Store that answers no field, leave the
 * witness absent.
 */

import { describe, expect, expectTypeOf, it } from "vitest";
import { InMemoryUserRepository } from "#/repositories/InMemoryUserRepository.mjs";
import type { User } from "#/repositories/types.mjs";
import {
	type MfaEnrollmentWitness,
	readMfaEnrollmentWitness,
	supportsMfaEnrollmentWitness,
	type UserRepository,
} from "#/repositories/UserRepository.mjs";

const verifyOnly: UserRepository = {
	authenticate: async () => null,
	authenticateByToken: async () => null,
};

describe("the MFA enrollment witness (D12)", () => {
	it("is a boolean the Store may answer on User", () => {
		expectTypeOf<User["mfaEnrolled"]>().toEqualTypeOf<boolean | undefined>();
		expect(true).toBe(true);
	});

	it("is written through an optional UserRepository capability", () => {
		expectTypeOf<UserRepository["markMfaEnrolled"]>().toEqualTypeOf<
			((subject: string, enrolled: boolean) => Promise<void>) | undefined
		>();
		expect(true).toBe(true);
	});

	it("is detected by method presence, and narrows the repository", async () => {
		expect(supportsMfaEnrollmentWitness(verifyOnly)).toBe(false);
		expect(
			supportsMfaEnrollmentWitness({
				...verifyOnly,
				markMfaEnrolled: "yes",
			} as unknown as UserRepository),
		).toBe(false);

		const marked: [string, boolean][] = [];
		const writing: UserRepository = {
			...verifyOnly,
			markMfaEnrolled: async (subject, enrolled) => {
				marked.push([subject, enrolled]);
			},
		};
		expect(supportsMfaEnrollmentWitness(writing)).toBe(true);
		if (!supportsMfaEnrollmentWitness(writing)) throw new Error("unreachable");
		expectTypeOf(writing.markMfaEnrolled).toEqualTypeOf<
			(subject: string, enrolled: boolean) => Promise<void>
		>();
		await writing.markMfaEnrolled("user-1", true);
		await writing.markMfaEnrolled("user-1", false);
		expect(marked).toEqual([
			["user-1", true],
			["user-1", false],
		]);
	});

	it("cannot be written through the bundled in-memory repository, which answers what its entries carry", async () => {
		const repo = new InMemoryUserRepository(
			new Map([
				["alice", { password: "secret123", id: "u1", mfaEnrolled: true }],
				["bob", { password: "secret456", id: "u2" }],
			]),
		);
		expect(supportsMfaEnrollmentWitness(repo)).toBe(false);
		expect((await repo.authenticate("alice", "secret123"))?.mfaEnrolled).toBe(true);
		expect((await repo.authenticate("bob", "secret456"))?.mfaEnrolled).toBeUndefined();
	});
});

/*
 * One reading of the witness, three answers. A Store that answers `1` or
 * `"true"` passes a shape check that only asks for an object, and read as
 * `=== true` it would silently be no witness — the downgrade D12 exists to
 * prevent. So a value that is neither a boolean nor absent is malformed: the
 * coordinator answers it 503, logged once, and never opens a first binding.
 */
describe("readMfaEnrollmentWitness (D12)", () => {
	it("answers enrolled for true, and not_enrolled for false or absent", () => {
		expect(readMfaEnrollmentWitness({ id: "u1", mfaEnrolled: true })).toBe("enrolled");
		expect(readMfaEnrollmentWitness({ id: "u1", mfaEnrolled: false })).toBe("not_enrolled");
		expect(readMfaEnrollmentWitness({ id: "u1" })).toBe("not_enrolled");
		expect(readMfaEnrollmentWitness({ id: "u1", mfaEnrolled: undefined })).toBe("not_enrolled");
	});

	it("answers malformed for any other value, never not_enrolled", () => {
		for (const value of [1, 0, "true", "false", "", null, {}, [], Number.NaN]) {
			expect(readMfaEnrollmentWitness({ id: "u1", mfaEnrolled: value }), String(value)).toBe(
				"malformed",
			);
		}
	});

	it("reads a User and the session's user snapshot alike", () => {
		const user: User = { id: "u1", username: "alice", mfaEnrolled: true };
		const snapshot: Readonly<Record<string, unknown>> = { id: "u1", mfaEnrolled: "yes" };
		expect(readMfaEnrollmentWitness(user)).toBe("enrolled");
		expect(readMfaEnrollmentWitness(snapshot)).toBe("malformed");
		expectTypeOf<MfaEnrollmentWitness>().toEqualTypeOf<"enrolled" | "not_enrolled" | "malformed">();
	});
});
