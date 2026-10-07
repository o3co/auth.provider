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
 * A `UserRepository` double for the consumers of the subject lookup
 * (`findBySubject`): it holds users by `id`, records every subject it is
 * asked for, and can leave the capability out or stand for a Store that
 * cannot answer. It authenticates nobody. Published on
 * `@o3co/auth-provider-core/testing`.
 */

import type { User } from "../repositories/types.mjs";
import type { UserRepository } from "../repositories/UserRepository.mjs";

export interface TestUserRepositoryOptions {
	/** The users `findBySubject` answers, keyed by their `id`; two with one `id` are refused. */
	readonly users?: readonly User[];
	/** `false` leaves `findBySubject` out, a repository without the capability. Default `true`. */
	readonly subjectLookup?: boolean;
	/** Thrown by `findBySubject`: a Store that cannot answer. */
	readonly unavailable?: unknown;
}

export interface TestUserRepository extends UserRepository {
	/** Every subject `findBySubject` was asked for, in order. */
	readonly lookups: readonly string[];
}

/** A `UserRepository` double for tests of the subject lookup's consumers. */
export function createTestUserRepository(
	options: TestUserRepositoryOptions = {},
): TestUserRepository {
	const users = new Map<string, User>();
	for (const user of options.users ?? []) {
		if (users.has(user.id)) {
			throw new Error(`createTestUserRepository: two users have the id ${user.id}`);
		}
		users.set(user.id, user);
	}
	const lookups: string[] = [];
	const findBySubject = async (subject: string): Promise<User | null> => {
		lookups.push(subject);
		if (options.unavailable !== undefined) throw options.unavailable;
		return users.get(subject) ?? null;
	};
	return {
		lookups,
		authenticate: async () => null,
		authenticateByToken: async () => null,
		...(options.subjectLookup === false ? {} : { findBySubject }),
	};
}
