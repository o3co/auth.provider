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
import type {
	FederatedIdentityLink,
	LinkFederatedIdentityResult,
	UserRepository,
} from "./UserRepository.mjs";

const DUMMY_BCRYPT_PASSWORD_HASH = "$2b$10$39.FBAWt.ck.rbQbPhmLOOPkwFxWEPZEYA3HR07Lr2k5OYqk.vRSi";
const BCRYPT_HASH_RE = /^\$2[aby]\$/;

export const UserEntrySchema = z
	.object({
		password: z.string().min(1),
		id: z.string().optional(),
	})
	.catchall(z.unknown());

export type UserEntry = z.infer<typeof UserEntrySchema>;

export class InMemoryUserRepository implements UserRepository {
	private users: Map<string, UserEntry>;
	/**
	 * #482: identities linked at runtime, token → username. In memory only —
	 * a restart forgets them. This repository is the development and test
	 * adapter; a deployment's Store persists its own links.
	 */
	private readonly linkedTokens = new Map<string, string>();

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

		const stored = entry?.password ?? DUMMY_BCRYPT_PASSWORD_HASH;
		const isBcrypt = BCRYPT_HASH_RE.test(stored);

		let match: boolean;
		if (isBcrypt) {
			match = await bcrypt.compare(password, stored);
		} else {
			// Pay the bcrypt cost on the plain-text path too, so that timing
			// converges across unknown-user / known-bcrypt / known-plain. The
			// result is discarded — correctness comes from timingSafeEqual.
			await bcrypt.compare(password, DUMMY_BCRYPT_PASSWORD_HASH);
			const a = Buffer.from(password);
			const b = Buffer.from(stored);
			match = a.length === b.length && crypto.timingSafeEqual(a, b);
		}

		if (!entry) return null;
		if (!match) return null;
		return this.toUser(username, entry);
	}

	async authenticateByToken(token: string): Promise<User | null> {
		const linked = this.linkedTokens.get(token);
		if (linked !== undefined) {
			const entry = this.users.get(linked);
			if (entry) return this.toUser(linked, entry);
		}
		for (const [username, entry] of this.users) {
			if ((entry as Record<string, unknown>).token === token) {
				return this.toUser(username, entry);
			}
		}
		return null;
	}
	/** #482 — see {@link UserRepository.linkFederatedIdentity}. In memory only. */
	async linkFederatedIdentity(
		userId: string,
		identity: FederatedIdentityLink,
	): Promise<LinkFederatedIdentityResult> {
		const target = [...this.users.entries()].find(
			([username, entry]) => (entry.id ?? username) === userId,
		);
		if (!target) return { ok: false, reason: "refused", description: "unknown user" };
		const [username, entry] = target;
		const holder =
			this.linkedTokens.get(identity.token) ??
			[...this.users.entries()].find(
				([, candidate]) => (candidate as Record<string, unknown>).token === identity.token,
			)?.[0];
		if (holder !== undefined && holder !== username) {
			return {
				ok: false,
				reason: "conflict",
				description: "identity already linked to another user",
			};
		}
		this.linkedTokens.set(identity.token, username);
		return { ok: true, user: this.toUser(username, entry) };
	}
}
