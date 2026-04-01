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

import crypto from "node:crypto";
import bcrypt from "bcrypt";
import { z } from "zod";
import type { User } from "./types.mjs";
import type { UserRepository } from "./UserRepository.mjs";

export const UserEntrySchema = z
	.object({
		password: z.string().min(1),
		id: z.string().optional(),
	})
	.catchall(z.unknown());

export type UserEntry = z.infer<typeof UserEntrySchema>;

export class StaticUserRepository implements UserRepository {
	private users: Map<string, UserEntry>;

	constructor(users: Map<string, UserEntry>) {
		this.users = users;
	}

	private toUser(username: string, entry: UserEntry): User {
		const { password: _, ...rest } = entry;
		return {
			id: entry.id ?? username,
			username,
			...rest,
		};
	}

	async authenticate(username: string, password: string): Promise<User | null> {
		const entry = this.users.get(username);
		if (!entry) return null;

		const stored = entry.password;
		const isBcrypt = /^\$2[aby]\$/.test(stored);

		let match: boolean;
		if (isBcrypt) {
			match = await bcrypt.compare(password, stored);
		} else {
			const a = Buffer.from(password);
			const b = Buffer.from(stored);
			match = a.length === b.length && crypto.timingSafeEqual(a, b);
		}

		if (!match) return null;
		return this.toUser(username, entry);
	}

	async authenticateByToken(token: string): Promise<User | null> {
		for (const [username, entry] of this.users) {
			if ((entry as Record<string, unknown>).token === token) {
				return this.toUser(username, entry);
			}
		}
		return null;
	}
}
