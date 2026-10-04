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
 * participants and pending close work — is one hash, `${prefix}s:{<sid>}`
 * (the sid as base64url of its JSON, so no sid moves the hash tag), with one
 * expiry (`PEXPIREAT`): `expiresAt` plus `DEFAULT_CLOCK_SKEW_MS`, raised by
 * the closing commit to the later of that and the commit plus `retainMs`. The
 * record therefore lapses whole. Each member is one script on that key,
 * judged on the server's clock.
 *
 * Every write is refused at or after a deadline the adapter stamps at issue
 * (`internal/write-deadline.mts`), so it commits within W of its issue or
 * never. `open`, `join` and `completeIf` keep their answer under a replay key
 * of their own on the record's slot until the clock skew past that deadline,
 * so a copy the driver sends again answers as the first did and writes
 * nothing. A write answered `late`, or unanswered within the write timeout,
 * rejects with an unknown outcome. `beginClose` needs no replay key: a copy
 * that lands again finds the record closing or closed and writes nothing.
 *
 * `listClosing` reads a closing index, `${prefix}c:{closing}:sids` (a sorted
 * set of sids, every score 0, so it orders them by their bytes) and
 * `:deadlines` (each sid's latest close deadline), on a slot of its own, which
 * no script can write together with a record on Redis Cluster. So:
 *
 * - `beginClose` adds the sid, with the close's deadline, before its closing
 *   commit, which carries the same deadline. A close that cannot add it
 *   rejects before it commits, so every closing record has an entry.
 * - The listing re-reads each listed sid's state and names only closing ones.
 *   It removes an entry whose record is not closing only when the index's
 *   clock was past its deadline plus the clock skew before that read: no
 *   close that added it can commit afterwards, and a later close raises the
 *   deadline, which the removal checks.
 * - The step that closes a record removes its entry when the record outlives
 *   the entry's deadline plus the skew: every close that added it then finds
 *   the record closed.
 *
 * The store assumes the app's and the servers' clocks agree within the
 * declared skew, acknowledged writes are not rolled back, and `noeviction`
 * (the boot check in `internal/session-lifecycle-eviction.mts`).
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
import type { SessionClosingIndexKeys, SessionLifecycleStoreClient } from "./clients.mjs";
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

/** How many index entries one listing step reads. */
const INDEX_PAGE_SIZE = 100;

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

const META_FIELDS = new Set(["sub", "state", "exp", "gen", "until", "np", "nw", "cause", "at"]);

/**
 * The record a hash holds, with its generation; a field outside the layout
 * (`clients/session-lifecycle.mts`) or one it cannot read throws.
 */
const recordOf = (
	fields: Readonly<Record<string, string>>,
): Versioned<SessionLifecycleRecord> & { readonly retainUntilMs: number } => {
	const participants: SessionParticipant[] = [];
	const pending: string[] = [];
	for (const [field, value] of Object.entries(fields)) {
		if (field.startsWith("p:")) {
			const item = field.slice(2);
			const colon = item.indexOf(":");
			if (colon <= 0) throw malformed("a participant field");
			participants.push({
				kind: item.slice(0, colon) as SessionParticipant["kind"],
				id: item.slice(colon + 1),
				data: value,
			});
		} else if (field.startsWith("w:")) {
			pending.push(field.slice(2));
		} else if (!META_FIELDS.has(field)) {
			throw malformed("an unknown field");
		}
	}
	participants.sort((a, b) => byBytes(sessionCloseItemOf(a), sessionCloseItemOf(b)));
	pending.sort(byBytes);
	const cause = fields.cause;
	const value = {
		sub: fields.sub,
		state: fields.state,
		expiresAt: instantOf(fields, "exp"),
		participants,
		close: cause === undefined ? undefined : { cause, closingAt: instantOf(fields, "at"), pending },
	} as SessionLifecycleRecord;
	return {
		value,
		generation: fields.gen as Versioned<SessionLifecycleRecord>["generation"],
		retainUntilMs: instantOf(fields, "until").getTime(),
	};
};

export function createRedisSessionLifecycleStore(
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

	const recordKey = (sid: string): string => `${prefix}s:{${keyPart(sid)}}`;
	/** The replay key of the write `writeId` to `key`: never `null`, as no record key holds a stray brace. */
	const replayKey = (key: string, writeId: string): string =>
		replayKeyOf(key, prefix, writeId) as string;
	const index: SessionClosingIndexKeys = {
		sids: `${prefix}c:{closing}:sids`,
		deadlines: `${prefix}c:{closing}:deadlines`,
	};

	/**
	 * Removes a closed record's entry when the record outlives every close
	 * that added it. Housekeeping only: a failure leaves the entry, which the
	 * listing removes later.
	 */
	const forgetClosed = async (sid: string, retainUntilMs: number): Promise<void> => {
		try {
			await client.pruneClosingOutlived(index, sid, retainUntilMs, CLOCK_SKEW_MS);
		} catch {
			// The entry stays until a listing passes it.
		}
	};

	return {
		kind: "redis",

		async open(sid, sub, expiresAt) {
			checkKey(sid, "sid");
			checkKey(sub, "sub");
			const expiresAtMs = checkExpiresAt(expiresAt);
			const key = recordKey(sid);
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
			const key = recordKey(sid);
			const generation = newStoreGeneration();
			const outcome = await withWriteDeadline(
				(deadlineMs) =>
					client.joinRecord(key, {
						deadlineMs,
						replayKey: replayKey(key, generation),
						clockSkewMs: CLOCK_SKEW_MS,
						item: sessionCloseItemOf(joining),
						data: joining.data,
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
			const key = recordKey(sid);
			const generation = newStoreGeneration();
			// The index first, at the commit's own deadline: a close that cannot
			// add its sid never commits, and none commits past that deadline.
			const reply = await withWriteDeadline(async (deadlineMs) => {
				if ((await client.addClosing(index, sid, deadlineMs)) === "late") return "late" as const;
				return client.beginCloseRecord(key, {
					deadlineMs,
					generation,
					cause,
					steps,
					perParticipant,
					retainMs,
				});
			}, unanswered("beginClose"));
			if (reply === "late") throw late("beginClose");
			if (reply === "missing") return readSessionCloseAnswer({ outcome: "missing" });
			const read = recordOf(reply);
			const answer = readSessionCloseAnswer({
				outcome: read.value.state as "closing" | "closed",
				generation: read.generation,
				record: read.value,
			});
			if (answer.outcome === "closed") await forgetClosed(sid, read.retainUntilMs);
			return answer;
		},

		async completeIf(sid, expected, item): Promise<ConditionalReplaceAnswer> {
			checkKey(sid, "sid");
			checkCloseItem(item);
			if (!isStoreGeneration(expected)) {
				throw new RangeError(
					`${OWNER}: expected is no well-formed generation; nothing was written`,
				);
			}
			const key = recordKey(sid);
			const generation = newStoreGeneration();
			const reply = await withWriteDeadline(
				(deadlineMs) =>
					client.completeRecordItem(key, {
						deadlineMs,
						replayKey: replayKey(key, generation),
						clockSkewMs: CLOCK_SKEW_MS,
						expected,
						item,
						generation,
					}),
				unanswered("completeIf"),
			);
			switch (reply.outcome) {
				case "late":
					throw late("completeIf");
				case "not_pending":
					throw new RangeError(`${OWNER}: ${item} is not pending; nothing was written`);
				case "missing":
				case "conflict":
					return readConditionalReplaceAnswer({ outcome: reply.outcome });
				case "closed":
					await forgetClosed(sid, reply.retainUntilMs);
					return readConditionalReplaceAnswer({ outcome: "updated", generation });
				default:
					return readConditionalReplaceAnswer({ outcome: "updated", generation });
			}
		},

		async read(sid) {
			checkKey(sid, "sid");
			const fields = await client.readRecord(recordKey(sid));
			if (fields === null) return readVersionedSessionLifecycle(null);
			const { value, generation } = recordOf(fields);
			return readVersionedSessionLifecycle({ value, generation });
		},

		async listClosing(limit, after = "") {
			checkListingLimit(limit);
			checkListingCursor(after);
			const closing: string[] = [];
			let cursor = after;
			for (;;) {
				const page = await client.closingPage(index, cursor, INDEX_PAGE_SIZE);
				const states = await Promise.all(
					page.entries.map(({ sid }) => client.recordState(recordKey(sid))),
				);
				const stale: { sid: string; deadline: string }[] = [];
				for (const [i, entry] of page.entries.entries()) {
					const state = states[i];
					if (state === "closing") {
						closing.push(entry.sid);
						if (closing.length === limit) break;
						continue;
					}
					if (state !== null && state !== "active" && state !== "closed") {
						throw malformed("state");
					}
					// Its close's deadline had passed on the index's clock before the
					// state was read: no close that added the entry can commit now.
					const deadline = entry.deadline === "" ? 0 : Number(entry.deadline);
					if (page.nowMs >= deadline + CLOCK_SKEW_MS) stale.push(entry);
				}
				await Promise.all(
					stale.map(({ sid, deadline }) => client.pruneClosingIf(index, sid, deadline)),
				);
				const last = page.entries.at(-1);
				if (closing.length === limit || page.entries.length < INDEX_PAGE_SIZE || !last) {
					return readSessionLifecycleListing(closing, limit, after);
				}
				cursor = last.sid;
			}
		},
	};
}
