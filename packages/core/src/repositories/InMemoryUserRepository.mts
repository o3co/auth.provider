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
	FederatedIdentityLookup,
	FederatedIdentityLookupResult,
	FederatedIdentityRegistration,
	LinkFederatedIdentityResult,
	UserRepository,
} from "./UserRepository.mjs";

/**
 * The highest bcrypt cost an entry may hold. A compare at cost 15 takes about
 * 32 times one at cost 10 (about 2 s against 60 ms on a current laptop core),
 * and holds one thread of Node's libuv pool for that long: four threads
 * unless `UV_THREADPOOL_SIZE` says otherwise, shared with file system, DNS
 * lookup, crypto and zlib work. Above it, each login would hold a thread for
 * several seconds.
 */
const MAX_BCRYPT_COST = 15;
/** bcrypt's own least cost. */
const MIN_BCRYPT_COST = 4;

/** A value starting with this is read as a bcrypt hash, never as plain text. */
const BCRYPT_MARK = "$2";
/** The bcrypt forms held: `$2a$` and `$2b$`, and `$2y$`, the same algorithm under PHP's name. */
const BCRYPT_FORM_RE = /^\$2[aby]\$/;
/** A well-formed hash of a held form: a two-digit cost, then a 22-character salt and 31-character hash. */
const BCRYPT_HASH_RE = /^\$2[aby]\$(\d{2})\$[./A-Za-z0-9]{53}$/;

/**
 * A hash of no known password, compared when there is no entry's hash to
 * compare, so an unknown user and a plain-text one pay a bcrypt compare too.
 * Its cost is replaced by the one {@link dummyHashFor} picks.
 */
const DUMMY_BCRYPT_PASSWORD_HASH = "$2b$10$39.FBAWt.ck.rbQbPhmLOOPkwFxWEPZEYA3HR07Lr2k5OYqk.vRSi";

/** A cost as a bcrypt hash writes it. */
const twoDigits = (cost: number): string => String(cost).padStart(2, "0");

/** Why `password` cannot be held, or `undefined`: plain text, or a well-formed hash at a cost held. */
function passwordRefusalOf(password: string): string | undefined {
	if (!password.startsWith(BCRYPT_MARK)) return undefined;
	if (!BCRYPT_FORM_RE.test(password)) {
		return 'a value starting with "$2" is read as a bcrypt hash, and only $2a$, $2b$ and $2y$ are supported';
	}
	const cost = bcryptCostOf(password);
	if (cost === undefined) {
		return "not a well-formed bcrypt hash: the prefix, a two-digit cost, a $, then 53 characters of bcrypt's alphabet (./A-Za-z0-9)";
	}
	if (cost < MIN_BCRYPT_COST || cost > MAX_BCRYPT_COST) {
		return `the bcrypt cost must be from ${twoDigits(MIN_BCRYPT_COST)} to ${twoDigits(MAX_BCRYPT_COST)}`;
	}
	return undefined;
}

/** The cost of a well-formed bcrypt hash, or `undefined` for anything else. */
function bcryptCostOf(password: string): number | undefined {
	const cost = BCRYPT_HASH_RE.exec(password)?.[1];
	return cost === undefined ? undefined : Number(cost);
}

/**
 * The dummy at the highest cost among the entries' hashes, or at cost 10
 * when none holds one. An unknown user cannot be told by its compare's time
 * from a user at that cost, and a cost-10 dummy beside costlier entries
 * would let the time tell them apart. Only the cost field changes: bcrypt
 * pays the whole cost whatever the hash it compares against.
 */
function dummyHashFor(entries: Iterable<UserEntry>): string {
	let highest: number | undefined;
	for (const { password } of entries) {
		const cost = bcryptCostOf(password);
		if (cost !== undefined) highest = Math.max(highest ?? cost, cost);
	}
	if (highest === undefined) return DUMMY_BCRYPT_PASSWORD_HASH;
	return `$2b$${twoDigits(highest)}$${DUMMY_BCRYPT_PASSWORD_HASH.slice(7)}`;
}

/** `hash` as the native compare takes it: `$2y$` is `$2b$` under another name. */
const comparable = (hash: string): string =>
	hash.startsWith("$2y$") ? `$2b$${hash.slice(4)}` : hash;

/**
 * One user's entry in a users file. Its key is its username, so the entry
 * carries none. `password` is plain text, or a bcrypt hash (any value starting
 * with `$2`): `$2a$`, `$2b$` or `$2y$`, well formed, at a cost from 04 to 15.
 * `id`, when set, is not empty; without it the username is the id. No message
 * quotes a value.
 */
export const UserEntrySchema = z
	.object({
		password: z
			.string()
			.min(1)
			.superRefine((password, ctx) => {
				const refusal = passwordRefusalOf(password);
				if (refusal !== undefined) ctx.addIssue({ code: z.ZodIssueCode.custom, message: refusal });
			}),
		id: z
			.string()
			.min(1, "must not be empty: set a non-empty id, or none to make the username the id")
			.optional(),
	})
	.catchall(z.unknown())
	.superRefine((entry, ctx) => {
		if (Object.hasOwn(entry, "username")) {
			ctx.addIssue({
				code: z.ZodIssueCode.custom,
				message: "must not be set: an entry's key is its username",
				path: ["username"],
			});
		}
	});

export type UserEntry = z.infer<typeof UserEntrySchema>;

/**
 * Refuse a user map that could not be served as written: an entry the schema
 * refuses, or two users with the same id (the `id`, or the username where none
 * is set). Each refusal names the users and the field, never a value.
 */
function assertHoldable(users: ReadonlyMap<string, UserEntry>): void {
	const byId = new Map<string, string>();
	for (const [username, entry] of users) {
		const parsed = UserEntrySchema.safeParse(entry);
		if (!parsed.success) {
			throw new Error(
				`InMemoryUserRepository: invalid entry "${username}": ${parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join(", ")}`,
			);
		}
		const id = entry.id ?? username;
		const holder = byId.get(id);
		if (holder !== undefined) {
			throw new Error(
				`InMemoryUserRepository: users "${holder}" and "${username}" have the same id; each user's id (its "id", or its username when it sets none) must be unique`,
			);
		}
		byId.set(id, username);
	}
}

export class InMemoryUserRepository implements UserRepository {
	private users: Map<string, UserEntry>;
	/** What an unknown user's and a plain-text user's compare runs against ({@link dummyHashFor}). */
	private readonly dummyHash: string;
	/**
	 * Identities linked at runtime, token → username. In memory only —
	 * a restart forgets them. This repository is the development and test
	 * adapter; a deployment's Store persists its own links.
	 */
	private readonly linkedTokens = new Map<string, string>();

	constructor(users: Map<string, UserEntry>) {
		assertHoldable(users);
		this.users = users;
		this.dummyHash = dummyHashFor(users.values());
	}

	private toUser(username: string, entry: UserEntry): User {
		const { password: _, ...rest } = entry;
		return {
			...rest,
			id: entry.id ?? username,
			username,
		};
	}

	async authenticate(username: string, password: string): Promise<User | null> {
		const entry = this.users.get(username);

		const stored = entry?.password ?? this.dummyHash;
		const isBcrypt = stored.startsWith(BCRYPT_MARK);

		let match: boolean;
		if (isBcrypt) {
			match = await bcrypt.compare(password, comparable(stored));
		} else {
			// Pay the bcrypt cost on the plain-text path too, so that timing
			// converges across unknown-user / known-bcrypt / known-plain. The
			// result is discarded — correctness comes from timingSafeEqual.
			await bcrypt.compare(password, this.dummyHash);
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
	/**
	 * See {@link UserRepository.supportsFederatedIdentityLookup}. No
	 * registration: this repository keys links by federation name and `sub`,
	 * and knows neither which registration a name is nor which other
	 * registrations of an IdP a person signed in through. A deployment that
	 * requires the lookup installs a Store that does, or records that it does
	 * not with `federation-grants.identityLookup = "unsupported"`.
	 */
	supportsFederatedIdentityLookup(
		_registration: FederatedIdentityRegistration,
		_identityClaims: readonly string[],
	): boolean {
		return false;
	}

	/**
	 * See {@link UserRepository.findSubjectByFederatedIdentity}.
	 * Always `indeterminate`, including where a name-and-`sub` entry matches: a
	 * hit under one registration does not show that no link under another names
	 * somebody else, and a miss does not show that nobody holds the person.
	 */
	async findSubjectByFederatedIdentity(
		_identity: FederatedIdentityLookup,
	): Promise<FederatedIdentityLookupResult> {
		return { kind: "indeterminate", reason: "registration_not_covered" };
	}

	/** See {@link UserRepository.linkFederatedIdentity}. In memory only. */
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
