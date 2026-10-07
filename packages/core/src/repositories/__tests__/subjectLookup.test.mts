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
 * The subject lookup: an optional `UserRepository` capability that answers
 * the `User` behind a `sub` this provider issues, for a grant that holds a
 * subject and no `User`. Detected by method presence.
 */

import { describe, expect, expectTypeOf, it } from "vitest";
import type { User } from "#/repositories/types.mjs";
import { supportsSubjectLookup, type UserRepository } from "#/repositories/UserRepository.mjs";

const verifyOnly: UserRepository = {
	authenticate: async () => null,
	authenticateByToken: async () => null,
};

describe("the subject lookup", () => {
	it("is an optional UserRepository capability", () => {
		expectTypeOf<UserRepository["findBySubject"]>().toEqualTypeOf<
			((subject: string) => Promise<User | null>) | undefined
		>();
		expect(true).toBe(true);
	});

	it("is detected by method presence, and narrows the repository", async () => {
		expect(supportsSubjectLookup(verifyOnly)).toBe(false);
		expect(
			supportsSubjectLookup({
				...verifyOnly,
				findBySubject: "yes",
			} as unknown as UserRepository),
		).toBe(false);

		const user: User = { id: "user-1", username: "alice", emailVerified: true };
		const looking: UserRepository = {
			...verifyOnly,
			findBySubject: async (subject) => (subject === user.id ? user : null),
		};
		expect(supportsSubjectLookup(looking)).toBe(true);
		if (!supportsSubjectLookup(looking)) throw new Error("unreachable");
		expectTypeOf(looking.findBySubject).toEqualTypeOf<(subject: string) => Promise<User | null>>();
		await expect(looking.findBySubject("user-1")).resolves.toBe(user);
		await expect(looking.findBySubject("user-2")).resolves.toBeNull();
	});
});
