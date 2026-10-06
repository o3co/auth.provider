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
 * Redis-backed `SessionLifecycleStore`. A session's whole record — its state,
 * participants and pending close work — is one hash with one expiry
 * (`PEXPIREAT`): `expiresAt` plus `DEFAULT_CLOCK_SKEW_MS`, raised by the
 * closing commit to the later of that and the commit plus `retainMs`. The
 * record therefore lapses whole.
 *
 * Each record lives in one of {@link SESSION_LIFECYCLE_SHARDS} shards, chosen
 * by {@link sessionLifecycleShardOf}, and each shard has a closing index (a
 * sorted set of the sids of its closing records) under the same hash tag, so
 * on Redis Cluster a record and its shard's index share one slot. A closing
 * commit adds the sid to the index and the completion that closes the record
 * removes it, in the script that writes the record, so the index never misses
 * a closing record and judges nothing by a clock. `listClosing` merges the
 * shards' indexes in byte order, and checks each sid's record in its shard's
 * own step, removing any whose record is no longer closing (one that lapsed
 * while closing, say).
 *
 * Every write is refused at or after a deadline the adapter stamps at issue
 * (`internal/write-deadline.mts`), so it commits within W of its issue or
 * never. `open`, `join` and `completeIf` keep their answer under a replay key
 * of their own on the record's slot until the clock skew past that deadline,
 * so a copy the driver sends again answers as the first did and writes
 * nothing. A write answered `late`, or unanswered within the write timeout,
 * rejects with an unknown outcome. `beginClose` needs no replay key: a copy
 * that lands again finds the record closing or closed and writes nothing.
 * Every member runs as a script, on the primary.
 *
 * The store assumes acknowledged writes are not rolled back and
 * `noeviction`, which the factory holds the server to
 * (`internal/eviction-policy.mts`): an evicted active or closing record drops
 * a live session's fence or loses its pending work, an evicted replay key lets
 * a resent write apply again, and the closing index carries no TTL, so an
 * evicted index hides a closing record from the listing.
 */

import {
	type ConditionalReplaceAnswer,
	DEFAULT_CLOCK_SKEW_MS,
	isStoreGeneration,
	newStoreGeneration,
	readConditionalReplaceAnswer,
	readSessionCloseAnswer,
	readSessionJoinAnswer,
	readSessionLifecycleListing,
	readSessionOpenAnswer,
	readVersionedSessionLifecycle,
	type SessionLifecycleRecord,
	type SessionLifecycleStore,
	type SessionParticipant,
	sessionCloseItemOf,
	type Versioned,
} from "@o3co/auth-provider-core";
import type { SessionLifecycleKeys, SessionLifecycleStoreClient } from "./clients.mjs";
import { requireNoEviction } from "./internal/eviction-policy.mjs";
import { replayKeyOf } from "./internal/replay-key.mjs";
import {
	checkCloseItem,
	checkCloseRequest,
	checkExpiresAt,
	checkKey,
	checkListingCursor,
	checkListingLimit,
	checkParticipant,
} from "./internal/session-lifecycle-input.mjs";
import { CLOCK_SKEW_MS, WRITE_TIMEOUT_MS, withWriteDeadline } from "./internal/write-deadline.mjs";

/** The key namespace the store defaults to. */
export const DEFAULT_REDIS_SESSION_LIFECYCLE_KEY_PREFIX = "ss:lc:";

/** The most participants one record holds by default. */
export const DEFAULT_REDIS_SESSION_LIFECYCLE_MAX_PARTICIPANTS = 1_000;

export interface RedisSessionLifecycleStoreOptions {
	readonly client: SessionLifecycleStoreClient;
	/** Outer namespace; the sid's hash tag follows it. Without a brace. Default `ss:lc:`. */
	readonly keyPrefix?: string;
	/** The most participants one record holds; a join past it rejects. Default 1000. */
	readonly maxParticipants?: number;
}

/** How many index entries one listing step reads from one shard. */
const INDEX_PAGE_SIZE = 100;

/**
 * How many shards the records and their closing indexes are spread over. A
 * constant of the key layout, not a setting: changing it moves every record
 * to another key. Sixteen spreads the store over up to sixteen Cluster
 * primaries, keeps each shard's index to a sixteenth of the closing sessions,
 * and keeps a listing to sixteen index reads per page.
 */
export const SESSION_LIFECYCLE_SHARDS = 16;

/**
 * The shard of `sid`: the 32-bit FNV-1a hash of its UTF-8 bytes, modulo
 * {@link SESSION_LIFECYCLE_SHARDS}.
 */
export function sessionLifecycleShardOf(sid: string): number {
	let hash = 0x811c9dc5;
	for (const byte of Buffer.from(sid, "utf8")) {
		hash ^= byte;
		hash = Math.imul(hash, 0x01000193) >>> 0;
	}
	return hash % SESSION_LIFECYCLE_SHARDS;
}

const OWNER = "SessionLifecycleStore (redis)";

const malformed = (what: string): TypeError =>
	new TypeError(`${OWNER}: the stored record is malformed: ${what}`);

const unknownOutcome = (operation: string, why: string): Error =>
	new Error(`${OWNER}: ${operation} ${why}; the outcome is unknown`);

/** Answered `late`: this copy wrote nothing, but another copy may have committed, or may still commit within W. */
const late = (operation: string): Error =>
	unknownOutcome(operation, "was answered past its deadline");

const unanswered = (operation: string) => (): Error =>
	unknownOutcome(operation, `had no answer within ${WRITE_TIMEOUT_MS} ms`);

/** A value inside a key name: base64url of its JSON, so it carries no brace into the hash tag. */
const keyPart = (value: string): string =>
	Buffer.from(JSON.stringify(value), "utf8").toString("base64url");

/** Ascending by UTF-8 bytes, so a record reads the same however its hash is laid out. */
const byBytes = (a: string, b: string): number =>
	Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));

const INTEGER = /^(0|-?[1-9]\d*)$/;

const instantOf = (fields: Readonly<Record<string, string>>, name: string): Date => {
	const raw = fields[name];
	if (raw === undefined || !INTEGER.test(raw) || !Number.isSafeInteger(Number(raw))) {
		throw malformed(name);
	}
	return new Date(Number(raw));
};

/** A participant's data, stored as a JSON string so that every string the port admits reads back as written. */
const dataOf = (stored: string): string => {
	let data: unknown;
	try {
		data = JSON.parse(stored);
	} catch {
		throw malformed("a participant's data");
	}
	if (typeof data !== "string") throw malformed("a participant's data");
	return data;
};

const META_FIELDS = new Set(["sub", "state", "exp", "gen", "until", "np", "nw", "cause", "at"]);

/**
 * The record a hash holds, with its generation; a field outside the layout
 * (`clients/session-lifecycle.mts`) or one it cannot read throws.
 */
const recordOf = (fields: Readonly<Record<string, string>>): Versioned<SessionLifecycleRecord> => {
	const participants: SessionParticipant[] = [];
	const ordinals = new Map<string, number>();
	const pending: string[] = [];
	for (const [field, value] of Object.entries(fields)) {
		if (field.startsWith("o:")) {
			const ordinal = Number(value);
			if (!INTEGER.test(value) || !Number.isSafeInteger(ordinal) || ordinal < 1) {
				throw malformed("a join ordinal");
			}
			ordinals.set(field.slice(2), ordinal);
		} else if (field.startsWith("p:")) {
			const item = field.slice(2);
			const colon = item.indexOf(":");
			if (colon <= 0) throw malformed("a participant field");
			participants.push({
				kind: item.slice(0, colon) as SessionParticipant["kind"],
				id: item.slice(colon + 1),
				data: dataOf(value),
			});
		} else if (field.startsWith("w:")) {
			pending.push(field.slice(2));
		} else if (!META_FIELDS.has(field)) {
			throw malformed("an unknown field");
		}
	}
	// In join order; a participant written with no ordinal after those with
	// one, by its item's bytes.
	participants.sort((a, b) => {
		const left = ordinals.get(sessionCloseItemOf(a)) ?? Number.POSITIVE_INFINITY;
		const right = ordinals.get(sessionCloseItemOf(b)) ?? Number.POSITIVE_INFINITY;
		return left === right
			? byBytes(sessionCloseItemOf(a), sessionCloseItemOf(b))
			: left < right
				? -1
				: 1;
	});
	pending.sort(byBytes);
	const cause = fields.cause;
	const value = {
		sub: fields.sub,
		state: fields.state,
		expiresAt: instantOf(fields, "exp"),
		participants,
		close: cause === undefined ? undefined : { cause, closingAt: instantOf(fields, "at"), pending },
	} as SessionLifecycleRecord;
	instantOf(fields, "until");
	return { value, generation: fields.gen as Versioned<SessionLifecycleRecord>["generation"] };
};

/**
 * The Redis {@link SessionLifecycleStore}. It resolves once the server's
 * eviction policy passes the gate (`internal/eviction-policy.mts`); an option
 * it cannot use rejects before the server is asked.
 */
export async function createRedisSessionLifecycleStore(
	options: RedisSessionLifecycleStoreOptions,
): Promise<SessionLifecycleStore> {
	const store = buildRedisSessionLifecycleStore(options);
	await requireNoEviction("sessionLifecycleStore", () => options.client.durability(), {
		reason: "session-lifecycle-store-evictable",
		holds:
			"sessions' records, writes' replay keys and the closing index, and losing one lets a closed session be opened and joined again, a resent write apply again, or a closing session drop out of the listing that resumes its work",
	});
	return store;
}

function buildRedisSessionLifecycleStore(
	options: RedisSessionLifecycleStoreOptions,
): SessionLifecycleStore {
	const { client } = options;
	const prefix = options.keyPrefix ?? DEFAULT_REDIS_SESSION_LIFECYCLE_KEY_PREFIX;
	if (prefix.includes("{") || prefix.includes("}")) {
		// A brace would open a hash tag of its own, and a record's keys would
		// stop sharing one slot.
		throw new RangeError(`${OWNER}: keyPrefix must not contain a brace`);
	}
	const maxParticipants =
		options.maxParticipants ?? DEFAULT_REDIS_SESSION_LIFECYCLE_MAX_PARTICIPANTS;
	if (!Number.isSafeInteger(maxParticipants) || maxParticipants < 1) {
		throw new RangeError(
			`${OWNER}: maxParticipants must be a whole number from 1 (got ${String(maxParticipants)})`,
		);
	}

	/** The hash tag a shard's records, replay keys and closing index share. */
	const tagOf = (shard: number): string => `{lc:${shard}}`;
	const recordIn = (shard: number, sid: string): string =>
		`${prefix}${tagOf(shard)}:s:${keyPart(sid)}`;
	const indexOf = (shard: number): string => `${prefix}${tagOf(shard)}:closing`;
	const keysOf = (sid: string): SessionLifecycleKeys => {
		const shard = sessionLifecycleShardOf(sid);
		return { record: recordIn(shard, sid), index: indexOf(shard), sid };
	};
	/** The replay key of the write `writeId` to `key`, on its slot: `${prefix}w:{lc:<shard>}:<writeId>`. */
	const replayKey = (key: string, writeId: string): string =>
		replayKeyOf(key, prefix, writeId) as string;

	/**
	 * The closing sids of one shard after `after`, in order, read a page at a
	 * time as the merge asks for them.
	 */
	const shardReader = (shard: number, after: string) => {
		const buffer: string[] = [];
		let cursor = after;
		let done = false;
		return {
			head: (): string | undefined => buffer[0],
			take: (): string | undefined => buffer.shift(),
			async fill(): Promise<void> {
				while (buffer.length === 0 && !done) {
					const page = await client.closingPage(indexOf(shard), cursor, INDEX_PAGE_SIZE);
					if (page.length < INDEX_PAGE_SIZE) done = true;
					const last = page.at(-1);
					if (last === undefined) return;
					cursor = last;
					buffer.push(
						...(await client.confirmClosing(
							indexOf(shard),
							page.map((sid) => ({ sid, record: recordIn(shard, sid) })),
						)),
					);
				}
			},
		};
	};

	return {
		kind: "redis",

		async open(sid, sub, expiresAt) {
			checkKey(sid, "sid");
			checkKey(sub, "sub");
			const expiresAtMs = checkExpiresAt(expiresAt);
			const key = keysOf(sid).record;
			const generation = newStoreGeneration();
			const outcome = await withWriteDeadline(
				(deadlineMs) =>
					client.openRecord(key, {
						deadlineMs,
						replayKey: replayKey(key, generation),
						clockSkewMs: CLOCK_SKEW_MS,
						sub,
						expiresAtMs,
						retainUntilMs: expiresAtMs + DEFAULT_CLOCK_SKEW_MS,
						generation,
					}),
				unanswered("open"),
			);
			if (outcome === "late") throw late("open");
			return readSessionOpenAnswer({ outcome });
		},

		async join(sid, participant) {
			checkKey(sid, "sid");
			const joining = checkParticipant(participant);
			const key = keysOf(sid).record;
			const generation = newStoreGeneration();
			const outcome = await withWriteDeadline(
				(deadlineMs) =>
					client.joinRecord(key, {
						deadlineMs,
						replayKey: replayKey(key, generation),
						clockSkewMs: CLOCK_SKEW_MS,
						item: sessionCloseItemOf(joining),
						data: JSON.stringify(joining.data),
						generation,
						maxParticipants,
					}),
				unanswered("join"),
			);
			if (outcome === "late") throw late("join");
			if (outcome === "full") {
				throw new Error(
					`${OWNER}: a record holds at most ${maxParticipants} participants; nothing was written`,
				);
			}
			return readSessionJoinAnswer({ outcome });
		},

		async beginClose(sid, request) {
			checkKey(sid, "sid");
			const { cause, steps, perParticipant, retainMs } = checkCloseRequest(request);
			const generation = newStoreGeneration();
			const reply = await withWriteDeadline(
				(deadlineMs) =>
					client.beginCloseRecord(keysOf(sid), {
						deadlineMs,
						generation,
						cause,
						steps,
						perParticipant,
						retainMs,
					}),
				unanswered("beginClose"),
			);
			if (reply === "late") throw late("beginClose");
			if (reply === "missing") return readSessionCloseAnswer({ outcome: "missing" });
			const read = recordOf(reply);
			return readSessionCloseAnswer({
				outcome: read.value.state as "closing" | "closed",
				generation: read.generation,
				record: read.value,
			});
		},

		async completeIf(sid, expected, item): Promise<ConditionalReplaceAnswer> {
			checkKey(sid, "sid");
			checkCloseItem(item);
			if (!isStoreGeneration(expected)) {
				throw new RangeError(
					`${OWNER}: expected is no well-formed generation; nothing was written`,
				);
			}
			const keys = keysOf(sid);
			const generation = newStoreGeneration();
			const reply = await withWriteDeadline(
				(deadlineMs) =>
					client.completeRecordItem(keys, {
						deadlineMs,
						replayKey: replayKey(keys.record, generation),
						clockSkewMs: CLOCK_SKEW_MS,
						expected,
						item,
						generation,
					}),
				unanswered("completeIf"),
			);
			switch (reply) {
				case "late":
					throw late("completeIf");
				case "not_pending":
					throw new RangeError(`${OWNER}: ${item} is not pending; nothing was written`);
				case "missing":
				case "conflict":
					return readConditionalReplaceAnswer({ outcome: reply });
				default:
					return readConditionalReplaceAnswer({ outcome: "updated", generation });
			}
		},

		async read(sid) {
			checkKey(sid, "sid");
			const fields = await client.readRecord(keysOf(sid).record);
			if (fields === null) return readVersionedSessionLifecycle(null);
			const { value, generation } = recordOf(fields);
			return readVersionedSessionLifecycle({ value, generation });
		},

		async listClosing(limit, after = "") {
			checkListingLimit(limit);
			checkListingCursor(after);
			const shards = Array.from({ length: SESSION_LIFECYCLE_SHARDS }, (_, shard) =>
				shardReader(shard, after),
			);
			await Promise.all(shards.map((shard) => shard.fill()));
			const closing: string[] = [];
			while (closing.length < limit) {
				let next: (typeof shards)[number] | undefined;
				for (const shard of shards) {
					const head = shard.head();
					const best = next?.head();
					if (head !== undefined && (best === undefined || byBytes(head, best) < 0)) next = shard;
				}
				if (next === undefined) break;
				closing.push(next.take() as string);
				await next.fill();
			}
			return readSessionLifecycleListing(closing, limit, after);
		},
	};
}
