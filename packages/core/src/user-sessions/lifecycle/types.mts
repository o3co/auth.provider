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
 * The session lifecycle port: one record per sid that holds the session's
 * state (`active` → `closing` → `closed`, never backwards), who joined it,
 * and, from the close on, the close work still to do. Joining and the
 * closing commit are one atomic step each against that record, so no join
 * lands once a close has committed, and every part of a session's record
 * lapses at one retention.
 *
 * Its one caller is core's session lifecycle service; no other module reads
 * a generation, a state or a work item. Every answer is read through the
 * readers in `readers.mts`.
 */

import type {
	ConditionalReplaceAnswer,
	StoreGeneration,
	Versioned,
} from "../../adapters/conditionalWrite.mjs";

/** A session's states, in the only order it moves through them. */
export const SESSION_LIFECYCLE_STATES = Object.freeze(["active", "closing", "closed"] as const);
export type SessionLifecycleState = (typeof SESSION_LIFECYCLE_STATES)[number];

/** What may join a session: a relying party, a refresh-token family, an upstream federation. */
export const SESSION_PARTICIPANT_KINDS = Object.freeze(["rp", "family", "federation"] as const);
export type SessionParticipantKind = (typeof SESSION_PARTICIPANT_KINDS)[number];

/** Why a session is closed. The first close's cause is the one kept. */
export const SESSION_CLOSE_CAUSES = Object.freeze([
	"rp_logout",
	"session_logout",
	"subject_revocation",
	"operator_reset",
	"expiry",
] as const);
export type SessionCloseCause = (typeof SESSION_CLOSE_CAUSES)[number];

/**
 * The longest sid, sub or participant id, in UTF-16 code units (`length`).
 * Each is well-formed text, no lone surrogate, so its UTF-8 bytes name it
 * alone.
 */
export const SESSION_LIFECYCLE_MAX_KEY_LENGTH = 512;

/** The longest participant `data`, in UTF-16 code units (`length`). */
export const SESSION_PARTICIPANT_MAX_DATA_LENGTH = 8192;

/** The most sids one `listClosing` may ask for. */
export const SESSION_LIFECYCLE_MAX_LISTING = 1000;

/**
 * One participant of a session, unique by `kind` and `id`. `data` is the
 * service's, kept byte for byte and never read by a store (`""` for none).
 */
export interface SessionParticipant {
	readonly kind: SessionParticipantKind;
	readonly id: string;
	readonly data: string;
}

/** A close in progress or done: what the closing commit saved. */
export interface SessionClose {
	readonly cause: SessionCloseCause;
	/** When the closing commit happened, on the store's clock. */
	readonly closingAt: Date;
	/** The work items not yet completed. Never empty while `closing`, always empty once `closed`. */
	readonly pending: readonly string[];
}

/**
 * A session's lifecycle record. Every field is a required key. From the
 * closing commit on, `participants` is the snapshot that commit took, and
 * nothing joins it again. `participants` is in the order each first joined:
 * a repeat join replaces its `data` and does not move it.
 */
export interface SessionLifecycleRecord {
	readonly sub: string;
	readonly state: SessionLifecycleState;
	/** The session's own end. No join lands from it on, on the store's clock. */
	readonly expiresAt: Date;
	readonly participants: readonly SessionParticipant[];
	/** `undefined` while `active`; what the closing commit saved after. */
	readonly close: SessionClose | undefined;
}

/**
 * What a closing commit saves as the close work: one item per name in
 * `steps`, and one per participant in the snapshot whose kind is in
 * `perParticipant` (named by {@link sessionCloseItemOf}).
 */
export interface SessionCloseRequest {
	readonly cause: SessionCloseCause;
	/** Session-wide work items: distinct names of 1 to 64 of `a`–`z`, `0`–`9` and `_`, a letter first. */
	readonly steps: readonly string[];
	/** The participant kinds that each make one work item per participant. Distinct. */
	readonly perParticipant: readonly SessionParticipantKind[];
	/**
	 * The least the store keeps a closing record from its closing commit, in
	 * whole milliseconds on the store's clock, from 0 to a year. The store
	 * keeps it until the later of that and the session's `expiresAt` plus
	 * `DEFAULT_CLOCK_SKEW_MS`, through `closed`.
	 */
	readonly retainMs: number;
}

/**
 * `opened`: the record is written `active`, or was already, opened for the
 * same `sub` and `expiresAt`, and is left as it is.
 * `refused`: nothing written. The sid holds another record (another subject,
 * another end, or one closing or closed), or `expiresAt` is not after the
 * store's clock.
 */
export type SessionOpenAnswer = { readonly outcome: "opened" } | { readonly outcome: "refused" };

/**
 * `joined`: the participant is in the record, at a new generation, its `data`
 * replaced when it was already there.
 * `closed`: nothing written. The record is closing or closed, or the
 * session's `expiresAt` is not after the store's clock.
 * `missing`: nothing written. No live record.
 */
export type SessionJoinAnswer =
	| { readonly outcome: "joined" }
	| { readonly outcome: "closed" }
	| { readonly outcome: "missing" };

/**
 * `closing` or `closed`: the record after the call, at its generation, its
 * state the outcome. A record that was active is now closing, or closed when
 * the request made no work item; one already closing or closed is answered as
 * it is, its first close kept.
 * `missing`: nothing written. No live record.
 */
export type SessionCloseAnswer =
	| {
			readonly outcome: "closing" | "closed";
			readonly generation: StoreGeneration;
			readonly record: SessionLifecycleRecord;
	  }
	| { readonly outcome: "missing" };

/**
 * The session lifecycle store. Every member is one atomic step in the store
 * (docs/adapter-surface.md, "Conditional writes", rule 1), serialised with
 * every other on the sid, and every answer reflects every write acknowledged
 * before the call began, never a cache or a replica. Every write that changes
 * the record issues a new random generation (rules 2 and 8).
 *
 * A record is live within the store's retention: `expiresAt` plus
 * `DEFAULT_CLOCK_SKEW_MS` while active, and from the closing commit the later
 * of that and the commit plus the request's `retainMs`. Past it, the whole
 * record is gone at once, participants and close work included: `read`
 * answers `null`, a write `missing`, and `listClosing` no longer names it.
 *
 * A store that cannot answer rejects; it never answers `missing`, `null`,
 * `closed` or `refused` for an outage. A caller's input outside the port's
 * rules is a `RangeError`, with nothing written.
 */
export interface SessionLifecycleStore {
	readonly kind: string;

	/** Writes the record `active`, with no participant. Never over another record. */
	open(sid: string, sub: string, expiresAt: Date): Promise<SessionOpenAnswer>;

	/** Adds or replaces one participant, only while the record is active and the session has not ended. */
	join(sid: string, participant: SessionParticipant): Promise<SessionJoinAnswer>;

	/**
	 * Moves an active record to `closing` in one commit: it keeps the
	 * participants as the snapshot and saves the close work `request` makes of
	 * them. Idempotent: a record already closing or closed is answered as it
	 * is, with no write, so a repeat call answers the saved work at the
	 * current generation.
	 */
	beginClose(sid: string, request: SessionCloseRequest): Promise<SessionCloseAnswer>;

	/**
	 * Marks one pending work item done, only while the record is at
	 * `expected`, at a new generation; the record is `closed` in the same step
	 * once nothing is pending. `missing` and `conflict` write nothing. The
	 * generation is checked before the item: at `expected`, an item not
	 * pending is a `RangeError`, and so is an `expected` that is no
	 * well-formed generation (`isStoreGeneration`).
	 */
	completeIf(
		sid: string,
		expected: StoreGeneration,
		item: string,
	): Promise<ConditionalReplaceAnswer>;

	/** The live record and its generation, from one snapshot; `null` when there is none. */
	read(sid: string): Promise<Versioned<SessionLifecycleRecord> | null>;

	/**
	 * The sids of live records in `closing` that sort after `after` (`""`, the
	 * default, is the start), in ascending order of their UTF-8 bytes, at most
	 * `limit` of them (1 to {@link SESSION_LIFECYCLE_MAX_LISTING}): the first
	 * `limit` in that order. Paging with the last sid answered as the next
	 * `after` reaches every record that stays closing, however many others
	 * stay ahead of it. A record that has left `closing` before the call
	 * begins is not named.
	 */
	listClosing(limit: number, after?: string): Promise<readonly string[]>;
}

/** The work item one participant makes: its kind, a colon, its id. No step name holds a colon. */
export function sessionCloseItemOf(participant: Pick<SessionParticipant, "kind" | "id">): string {
	return `${participant.kind}:${participant.id}`;
}

// ComponentMap declaration-merge: an optional slot. Nothing reads it yet.
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly sessionLifecycleStore?: SessionLifecycleStore;
	}
}
