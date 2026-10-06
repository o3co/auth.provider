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
 * The session lifecycle store's client: one hash per session holding its
 * whole record, and per shard a closing index on the same Cluster slot as the
 * shard's records, so a write and its index change are one atomic step. Every
 * member runs on the primary (a script), never a replica: an answer reflects
 * every write acknowledged before it.
 *
 * A record is a hash with these fields, and no other:
 *
 * - `sub`, `state` (`active`, `closing` or `closed`), `exp` (the session's
 *   `expiresAt`, epoch ms), `gen` (the record's generation), `until` (the
 *   epoch ms the key expires at, `PEXPIREAT`), `np` (how many participants it
 *   holds), and from the close on `cause`, `at` (the closing commit's time on
 *   the server's clock, epoch ms) and `nw` (how many work items are pending);
 * - `p:<kind>:<id>`, one per participant, its value the participant's `data`
 *   as a JSON string;
 * - `o:<kind>:<id>`, one per participant, its join ordinal (1, 2, …), written
 *   when it first joins and kept by a repeat join: the order participants are
 *   answered in. A participant with no ordinal is answered after those with
 *   one, by its item's bytes;
 * - `w:<item>`, one per pending work item, its value `1`.
 *
 * The reader refuses a record with any other field, so a new field needs a
 * reader that tolerates it deployed before any writer that writes it.
 *
 * A shard's closing index is a sorted set of the sids of its closing records,
 * every score 0, so it orders them by their bytes. Integers are written in
 * decimal.
 */

import type { RedisDurability } from "./durability.mjs";

/** The deadline a write is refused at or after, and where it keeps its answer. */
export interface SessionLifecycleWriteDeadline {
	/** Epoch ms on the server's clock at or after which the write is refused (`late`), nothing read or written. */
	readonly deadlineMs: number;
	/**
	 * Where this write keeps its answer until `clockSkewMs` past `deadlineMs`
	 * (`SET … PXAT deadlineMs + clockSkewMs + 1`), on the record's Cluster
	 * slot: a copy of the write that reaches the server before then answers
	 * what the first copy answered and writes nothing.
	 */
	readonly replayKey: string;
	/** The clock skew allowed between the servers' clocks, by which the replay key outlives the deadline. */
	readonly clockSkewMs: number;
}

/** What `openRecord` writes. */
export interface SessionLifecycleOpenInput extends SessionLifecycleWriteDeadline {
	readonly sub: string;
	/** The session's `expiresAt`, epoch ms. */
	readonly expiresAtMs: number;
	/** When the key expires (`PEXPIREAT`), epoch ms. */
	readonly retainUntilMs: number;
	readonly generation: string;
}

/** What `joinRecord` writes. */
export interface SessionLifecycleJoinInput extends SessionLifecycleWriteDeadline {
	/** The participant's work item: its kind, a colon, its id. */
	readonly item: string;
	/** The participant's data, as a JSON string. */
	readonly data: string;
	readonly generation: string;
	/** The most participants the record may hold; a join past it answers `full`. */
	readonly maxParticipants: number;
}

/** What `beginCloseRecord` writes. A copy that lands again finds the record closing and writes nothing. */
export interface SessionLifecycleCloseInput {
	/** Epoch ms on the server's clock at or after which the close is refused (`late`). */
	readonly deadlineMs: number;
	readonly generation: string;
	readonly cause: string;
	readonly steps: readonly string[];
	readonly perParticipant: readonly string[];
	readonly retainMs: number;
}

/** What `completeRecordItem` checks and writes. */
export interface SessionLifecycleCompleteInput extends SessionLifecycleWriteDeadline {
	readonly expected: string;
	readonly item: string;
	readonly generation: string;
}

/** Where a session lives: its record's key, its shard's closing index on the same slot, and its sid. */
export interface SessionLifecycleKeys {
	readonly record: string;
	readonly index: string;
	readonly sid: string;
}

export interface SessionLifecycleStoreClient {
	/**
	 * Writes the record `active` (`PEXPIREAT input.retainUntilMs`) when there
	 * is none and `expiresAtMs` is after the server's clock; `opened` without
	 * a write for an active record of the same `sub` and `exp`; `refused`
	 * otherwise.
	 */
	openRecord(key: string, input: SessionLifecycleOpenInput): Promise<"opened" | "refused" | "late">;
	/**
	 * Adds or replaces the participant `p:<item>` while the record is active
	 * and its `exp` is after the server's clock: `closed` when not, `missing`
	 * for no record, `full` (nothing written, nothing kept) past
	 * `maxParticipants`.
	 */
	joinRecord(
		key: string,
		input: SessionLifecycleJoinInput,
	): Promise<"joined" | "closed" | "missing" | "full" | "late">;
	/**
	 * Moves an active record to `closing` (or `closed` when it makes no work
	 * item), saving the work items, the cause and the server's time, raising
	 * the key's expiry to the later of `until` and that time plus `retainMs`,
	 * and adding the sid to its shard's index when it is closing, in one step.
	 * A record already closing or closed is left as it is. Answers the
	 * record's fields after the step, or `missing` for no record.
	 */
	beginCloseRecord(
		keys: SessionLifecycleKeys,
		input: SessionLifecycleCloseInput,
	): Promise<"missing" | "late" | Readonly<Record<string, string>>>;
	/**
	 * Removes the pending item `w:<item>` only while the record's `gen` is
	 * `expected`; with the last one, the record is `closed` and its sid leaves
	 * the index, in the same step. `not_pending`: nothing written or kept.
	 */
	completeRecordItem(
		keys: SessionLifecycleKeys,
		input: SessionLifecycleCompleteInput,
	): Promise<"updated" | "closed" | "missing" | "conflict" | "not_pending" | "late">;
	/** The record's fields in one step, or `null` for no key. */
	readRecord(key: string): Promise<Readonly<Record<string, string>> | null>;
	/** Up to `count` sids of the index after `after` (`""`: the start), in order. */
	closingPage(index: string, after: string, count: number): Promise<readonly string[]>;
	/**
	 * Of `sessions` (all on `index`'s shard), the sids whose record is closing,
	 * in the order given; every other one leaves the index, in the same step.
	 */
	confirmClosing(
		index: string,
		sessions: readonly { readonly sid: string; readonly record: string }[],
	): Promise<readonly string[]>;
	/** What the server says about keeping what it is written, read once by the factory for its eviction gate. */
	durability(): Promise<RedisDurability>;
}
