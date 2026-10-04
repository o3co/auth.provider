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
 * whole record, one atomic step per write on it, and the closing index the
 * store lists closing sessions from.
 *
 * A record is a hash with these fields, and no other:
 *
 * - `sub`, `state` (`active`, `closing` or `closed`), `exp` (the session's
 *   `expiresAt`, epoch ms), `gen` (the record's generation), `until` (the
 *   epoch ms the key expires at, `PEXPIREAT`), `np` (how many participants it
 *   holds), and from the close on `cause`, `at` (the closing commit's time on
 *   the server's clock, epoch ms) and `nw` (how many work items are pending);
 * - `p:<kind>:<id>`, one per participant, its value the participant's `data`;
 * - `w:<item>`, one per pending work item, its value `1`.
 *
 * Every field lives and lapses with the one key. Integers are written in
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

/**
 * `updated`: the item is done and others are pending. `closed`: it was the
 * last, the record is closed, and its key expires at `retainUntilMs`.
 * `not_pending`: the generation matched and the item is not pending; nothing
 * written. `late`: refused at or after the deadline; this copy wrote nothing.
 */
export type SessionLifecycleCompleteReply =
	| { readonly outcome: "updated" | "missing" | "conflict" | "not_pending" | "late" }
	| { readonly outcome: "closed"; readonly retainUntilMs: number };

/** The closing index's two keys, on one Cluster slot. */
export interface SessionClosingIndexKeys {
	/** A sorted set of sids, every score 0, so it orders them by their bytes. */
	readonly sids: string;
	/** A hash: sid → the latest deadline of a close that added it, epoch ms. */
	readonly deadlines: string;
}

/** One page of the closing index, read in one step. */
export interface SessionClosingPage {
	/** The index server's clock when the page was read, epoch ms. */
	readonly nowMs: number;
	/** The sids after the cursor, in order, each with its stored deadline as written (`""` for none). */
	readonly entries: readonly { readonly sid: string; readonly deadline: string }[];
}

export interface SessionLifecycleStoreClient {
	/**
	 * Writes the record `active` at `key` (`PEXPIREAT input.retainUntilMs`)
	 * when there is none and `expiresAtMs` is after the server's clock;
	 * `opened` without a write for an active record of the same `sub` and
	 * `exp` whose session has not ended; `refused` otherwise.
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
	 * item), saving the work items, the cause and the server's time, and raises
	 * the key's expiry to the later of `until` and that time plus `retainMs`.
	 * A record already closing or closed is left as it is. Answers the record's
	 * fields after the step, or `missing` for no record.
	 */
	beginCloseRecord(
		key: string,
		input: SessionLifecycleCloseInput,
	): Promise<"missing" | "late" | Readonly<Record<string, string>>>;
	/** Removes the pending item `w:<item>` only while the record's `gen` is `expected`. */
	completeRecordItem(
		key: string,
		input: SessionLifecycleCompleteInput,
	): Promise<SessionLifecycleCompleteReply>;
	/** The record's fields in one step (`HGETALL`), or `null` for no key. */
	readRecord(key: string): Promise<Readonly<Record<string, string>> | null>;
	/** The record's `state` field (`HGET`), or `null` for no key. */
	recordState(key: string): Promise<string | null>;
	/**
	 * Adds `sid` to the closing index and raises its stored deadline to
	 * `deadlineMs`, in one step refused (`late`) at or after `deadlineMs` on the
	 * index server's clock.
	 */
	addClosing(
		index: SessionClosingIndexKeys,
		sid: string,
		deadlineMs: number,
	): Promise<"added" | "late">;
	/** Up to `count` sids after `after` (`""`: the start) and their stored deadlines, with the server's clock. */
	closingPage(
		index: SessionClosingIndexKeys,
		after: string,
		count: number,
	): Promise<SessionClosingPage>;
	/** Removes `sid` from the index only while its stored deadline is still `deadline`. */
	pruneClosingIf(index: SessionClosingIndexKeys, sid: string, deadline: string): Promise<boolean>;
	/**
	 * Removes `sid` from the index only while its stored deadline plus
	 * `clockSkewMs` is no later than `retainUntilMs`.
	 */
	pruneClosingOutlived(
		index: SessionClosingIndexKeys,
		sid: string,
		retainUntilMs: number,
		clockSkewMs: number,
	): Promise<boolean>;
	/** What the server says about keeping what it is written, read once at boot for its eviction policy. */
	durability(): Promise<RedisDurability>;
}
