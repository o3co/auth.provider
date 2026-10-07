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
 * `createTestUserRepository`: a `UserRepository` double for a consumer of the
 * subject lookup. It holds users by `id`, answers `findBySubject` from them,
 * records every subject it is asked for, and can leave the capability out or
 * stand for a Store that cannot answer.
 */

import { describe, expect, it } from "vitest";
import { supportsSubjectLookup } from "#/repositories/UserRepository.mjs";
import { createTestUserRepository } from "#/testing/index.mjs";

const alice = { id: "user-1", username: "alice", emailVerified: true } as const;

describe("createTestUserRepository", () => {
	it("answers findBySubject from the users it holds, by id, and records each subject asked", async () => {
		const repository = createTestUserRepository({ users: [alice] });
		expect(supportsSubjectLookup(repository)).toBe(true);
		await expect(repository.findBySubject?.("user-1")).resolves.toEqual(alice);
		await expect(repository.findBySubject?.("user-2")).resolves.toBeNull();
		expect(repository.lookups).toEqual(["user-1", "user-2"]);
	});

	it("authenticates nobody: the double stands for a subject lookup alone", async () => {
		const repository = createTestUserRepository({ users: [alice] });
		await expect(repository.authenticate("alice", "x")).resolves.toBeNull();
		await expect(repository.authenticateByToken("google:1")).resolves.toBeNull();
	});

	it("leaves the capability out when asked to", () => {
		const repository = createTestUserRepository({ users: [alice], subjectLookup: false });
		expect(supportsSubjectLookup(repository)).toBe(false);
		expect("findBySubject" in repository).toBe(false);
	});

	it("throws the given error from findBySubject, standing for a Store that cannot answer, and still records the subject", async () => {
		const outage = new Error("store down");
		const repository = createTestUserRepository({ users: [alice], unavailable: outage });
		await expect(repository.findBySubject?.("user-1")).rejects.toBe(outage);
		expect(repository.lookups).toEqual(["user-1"]);
	});

	it("refuses two users with one id", () => {
		expect(() => createTestUserRepository({ users: [alice, { ...alice }] })).toThrow(/user-1/);
	});
});
