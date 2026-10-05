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
 * The in-process `SessionLifecycleStore`: one process's records, lost on a
 * restart, so it fences joins and closes within one replica only. Every
 * member checks and writes with no `await` between, so each is one step in
 * this process. A record lapses whole at its retention, judged on the
 * store's clock. It holds at most `maxEntries` records and `maxParticipants`
 * per record. Full, it drops lapsed records, then evicts the `closed` record
 * kept the shortest, and rejects only when every record is active or
 * closing. A closed record's work is done, its user session deleted among
 * it, so the session lifecycle reads no live session for that sid whether
 * the record is kept or not; an active or closing record is never evicted,
 * since that would let a closed session be joined or leave its work undone.
 */

import {
	type ConditionalReplaceAnswer,
	isStoreGeneration,
	newStoreGeneration,
	type StoreGeneration,
} from "../../adapters/conditionalWrite.mjs";
import { DEFAULT_CLOCK_SKEW_MS } from "../../jwt/verify.mjs";
import { MAX_MEMORY_STORE_ENTRIES, usableMaxEntries } from "../../single-use/max-entries.mjs";
import {
	checkSessionCloseItem,
	checkSessionCloseRequest,
	checkSessionExpiresAt,
	checkSessionLifecycleKey,
	checkSessionListingCursor,
	checkSessionListingLimit,
	checkSessionParticipant,
	compareSessionSids,
} from "./readers.mjs";
import {
	type SessionClose,
	type SessionLifecycleRecord,
	type SessionLifecycleStore,
	type SessionParticipant,
	sessionCloseItemOf,
} from "./types.mjs";

export const DEFAULT_MEMORY_SESSION_LIFECYCLE_MAX_ENTRIES = 100_000;
export const DEFAULT_MEMORY_SESSION_LIFECYCLE_MAX_PARTICIPANTS = 1_000;

export interface InMemorySessionLifecycleStoreOptions {
	/** The most records it holds. Default {@link DEFAULT_MEMORY_SESSION_LIFECYCLE_MAX_ENTRIES}. */
	readonly maxEntries?: number;
	/** The most participants one record holds. Default {@link DEFAULT_MEMORY_SESSION_LIFECYCLE_MAX_PARTICIPANTS}. */
	readonly maxParticipants?: number;
	/** Epoch milliseconds. Default `Date.now`. */
	readonly now?: () => number;
}

interface Stored {
	readonly sub: string;
	readonly expiresAtMs: number;
	state: SessionLifecycleRecord["state"];
	/** Keyed by the participant's work item, in join order. */
	readonly participants: Map<string, SessionParticipant>;
	close:
		| {
				readonly cause: SessionClose["cause"];
				readonly closingAtMs: number;
				readonly pending: Set<string>;
		  }
		| undefined;
	/** When the whole record lapses, in epoch ms on the store's clock. */
	retainUntilMs: number;
	generation: StoreGeneration;
}

/** The record a stored entry holds, as a copy that shares nothing with it. */
const toRecord = (stored: Stored): SessionLifecycleRecord => ({
	sub: stored.sub,
	state: stored.state,
	expiresAt: new Date(stored.expiresAtMs),
	participants: [...stored.participants.values()].map((p) => ({
		kind: p.kind,
		id: p.id,
		data: p.data,
	})),
	close:
		stored.close === undefined
			? undefined
			: {
					cause: stored.close.cause,
					closingAt: new Date(stored.close.closingAtMs),
					pending: [...stored.close.pending],
				},
});

export function createInMemorySessionLifecycleStore(
	options: InMemorySessionLifecycleStoreOptions = {},
): SessionLifecycleStore {
	const owner = "createInMemorySessionLifecycleStore";
	const maxEntries = usableMaxEntries(
		options.maxEntries ?? DEFAULT_MEMORY_SESSION_LIFECYCLE_MAX_ENTRIES,
		owner,
	);
	const maxParticipants =
		options.maxParticipants ?? DEFAULT_MEMORY_SESSION_LIFECYCLE_MAX_PARTICIPANTS;
	if (
		!Number.isInteger(maxParticipants) ||
		maxParticipants <= 0 ||
		maxParticipants > MAX_MEMORY_STORE_ENTRIES
	) {
		throw new RangeError(
			`${owner}: maxParticipants must be a whole number from 1 to ${MAX_MEMORY_STORE_ENTRIES} (got ${String(maxParticipants)})`,
		);
	}
	const clock = options.now ?? Date.now;
	const records = new Map<string, Stored>();

	const now = (): number => {
		const at = clock();
		if (!Number.isFinite(at))
			throw new RangeError(`${owner}: the clock answered no finite instant`);
		return at;
	};

	/** The live entry of `sid` at `at`; a lapsed one is dropped. */
	const live = (sid: string, at: number): Stored | undefined => {
		const stored = records.get(sid);
		if (stored === undefined) return undefined;
		if (stored.retainUntilMs > at) return stored;
		records.delete(sid);
		return undefined;
	};

	return {
		kind: "memory",

		async open(sid, sub, expiresAt) {
			checkSessionLifecycleKey(sid, "sid");
			checkSessionLifecycleKey(sub, "sub");
			const expiresAtMs = checkSessionExpiresAt(expiresAt).getTime();
			const at = now();
			if (expiresAtMs <= at) return { outcome: "refused" };
			const stored = live(sid, at);
			if (stored !== undefined) {
				const same =
					stored.state === "active" && stored.sub === sub && stored.expiresAtMs === expiresAtMs;
				return { outcome: same ? "opened" : "refused" };
			}
			if (records.size >= maxEntries) {
				for (const [key, entry] of records) if (entry.retainUntilMs <= at) records.delete(key);
			}
			if (records.size >= maxEntries) {
				let evicted: [string, Stored] | undefined;
				for (const entry of records) {
					if (entry[1].state !== "closed") continue;
					if (evicted === undefined || entry[1].retainUntilMs < evicted[1].retainUntilMs) {
						evicted = entry;
					}
				}
				if (evicted === undefined) {
					throw new Error(
						`${owner}: full at ${maxEntries} records, none of them closed; nothing was written`,
					);
				}
				records.delete(evicted[0]);
			}
			records.set(sid, {
				sub,
				expiresAtMs,
				state: "active",
				participants: new Map(),
				close: undefined,
				retainUntilMs: expiresAtMs + DEFAULT_CLOCK_SKEW_MS,
				generation: newStoreGeneration(),
			});
			return { outcome: "opened" };
		},

		async join(sid, participant) {
			checkSessionLifecycleKey(sid, "sid");
			const joining = checkSessionParticipant(participant);
			const at = now();
			const stored = live(sid, at);
			if (stored === undefined) return { outcome: "missing" };
			if (stored.state !== "active" || stored.expiresAtMs <= at) return { outcome: "closed" };
			const item = sessionCloseItemOf(joining);
			if (!stored.participants.has(item) && stored.participants.size >= maxParticipants) {
				throw new Error(
					`${owner}: a record holds at most ${maxParticipants} participants; nothing was written`,
				);
			}
			stored.participants.set(item, { kind: joining.kind, id: joining.id, data: joining.data });
			stored.generation = newStoreGeneration();
			return { outcome: "joined" };
		},

		async beginClose(sid, request) {
			checkSessionLifecycleKey(sid, "sid");
			const { cause, steps, perParticipant, retainMs } = checkSessionCloseRequest(request);
			const at = now();
			const stored = live(sid, at);
			if (stored === undefined) return { outcome: "missing" };
			if (stored.state === "active") {
				const pending = new Set(steps);
				for (const [item, p] of stored.participants)
					if (perParticipant.includes(p.kind)) pending.add(item);
				stored.state = pending.size > 0 ? "closing" : "closed";
				stored.close = { cause, closingAtMs: at, pending };
				stored.retainUntilMs = Math.max(stored.retainUntilMs, at + retainMs);
				stored.generation = newStoreGeneration();
			}
			return {
				outcome: stored.state === "closing" ? "closing" : "closed",
				generation: stored.generation,
				record: toRecord(stored),
			};
		},

		async completeIf(sid, expected, item): Promise<ConditionalReplaceAnswer> {
			checkSessionLifecycleKey(sid, "sid");
			checkSessionCloseItem(item);
			if (!isStoreGeneration(expected)) {
				throw new RangeError(
					`${owner}: expected is no well-formed generation; nothing was written`,
				);
			}
			const stored = live(sid, now());
			if (stored === undefined) return { outcome: "missing" };
			if (stored.generation !== expected) return { outcome: "conflict" };
			if (stored.close === undefined || !stored.close.pending.has(item)) {
				throw new RangeError(`${owner}: ${item} is not pending; nothing was written`);
			}
			stored.close.pending.delete(item);
			if (stored.close.pending.size === 0) stored.state = "closed";
			stored.generation = newStoreGeneration();
			return { outcome: "updated", generation: stored.generation };
		},

		async read(sid) {
			checkSessionLifecycleKey(sid, "sid");
			const stored = live(sid, now());
			return stored === undefined
				? null
				: { value: toRecord(stored), generation: stored.generation };
		},

		async listClosing(limit, after = "") {
			checkSessionListingLimit(limit);
			checkSessionListingCursor(after);
			const at = now();
			const closing: string[] = [];
			for (const [sid, stored] of records) {
				if (stored.retainUntilMs <= at) records.delete(sid);
				else if (stored.state === "closing" && compareSessionSids(after, sid) < 0)
					closing.push(sid);
			}
			return closing.sort(compareSessionSids).slice(0, limit);
		},
	};
}
