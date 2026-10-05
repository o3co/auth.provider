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
 * The session lifecycle service, the one writer of `SessionLifecycleStore`
 * (session admission reads a record's state):
 * opens a session's record as it is established, joins a session, closes it
 * and runs the close work, says whether it is live, and resumes closes left
 * pending. Its callers see `opened` / `joined` / `refused`, `done` /
 * `pending`, `live` / `not_live` and `unavailable`;
 * generations, states, work items, the cause policy and the bridge to the
 * per-session stores stay here.
 *
 * A close commits first and then runs its work. Every item is safe to run
 * more than once and is recorded at the generation read, so two closes of one
 * session and the sweep may overlap. Items run in phases, each only once the
 * earlier ones are recorded, the user session and then the subject's index
 * entry last; the items of a phase run together, a close's notices and
 * family revocations at most `CLOSE_CONCURRENCY` at once, and a failed item
 * keeps the record closing.
 */

import {
	type ConditionalReplaceAnswer,
	readConditionalReplaceAnswer,
	type Versioned,
} from "../adapters/conditionalWrite.mjs";
import { MAX_DURATION_MS } from "../config/durations.mjs";
import type { FederationTokenStore } from "../federation-tokens/types.mjs";
import { consoleLogger } from "../logging/consoleLogger.mjs";
import type { EventLogger } from "../logging/Logger.mjs";
import { loggableError } from "../logging/loggableError.mjs";
import type { RefreshTokenFamilyRevocation } from "../refresh-token-family/types.mjs";
import { readRecord } from "../session-admission/live-session.mjs";
import {
	checkSessionExpiresAt,
	checkSessionLifecycleKey,
	checkSessionParticipant,
	isSessionLifecycleKey,
	readSessionCloseAnswer,
	readSessionJoinAnswer,
	readSessionLifecycleListing,
	readSessionOpenAnswer,
	readVersionedSessionLifecycle,
} from "../user-sessions/lifecycle/readers.mjs";
import {
	SESSION_CLOSE_CAUSES,
	type SessionCloseCause,
	type SessionCloseRequest,
	type SessionLifecycleRecord,
	type SessionLifecycleStore,
	type SessionParticipant,
	type SessionParticipantKind,
	sessionCloseItemOf,
} from "../user-sessions/lifecycle/types.mjs";
import type {
	RegisteredRP,
	SessionFamilyIndex,
	SessionFederationIndex,
	SessionRPRegistry,
	SubjectSessionIndex,
	UserSession,
	UserSessionStore,
} from "../user-sessions/types.mjs";
import { type BridgedClose, createSessionStoresBridge } from "./bridge.mjs";
import type { SessionCloseNotifier } from "./notifier.mjs";

/** The session a record is opened for: its subject and its own end. */
export interface SessionOpenRequest {
	readonly sub: string;
	/** The end the user session will carry. */
	readonly expiresAt: Date;
}

/**
 * `opened`: the session's record is active for that subject and end, written
 * now or already. `refused`: the sid holds another session's record (another
 * subject or end, or one closing or closed), or the end has passed; nothing
 * was written, and nothing is established on that sid. `unavailable`: the
 * store could not answer; nothing is established on it.
 */
export type SessionOpenOutcome =
	| { readonly outcome: "opened" }
	| { readonly outcome: "refused" }
	| { readonly outcome: "unavailable" };

/** What a join adds to a session. At least one is named. */
export interface SessionJoinRequest {
	/** A relying party that completed a token exchange in the session. */
	readonly rp?: RegisteredRP;
	/** The refresh-token family issued in it. Revoked by the service when the join is refused. */
	readonly familyId?: string;
	/** An upstream federation linked to it. Its tokens are removed by the service when the join is refused. */
	readonly federation?: string;
}

/**
 * `joined`: hand out what joined. `refused`: the session is closing, closed
 * or gone; hand out nothing (the service has already revoked the family and
 * removed the federation's tokens). `unavailable`: a store could not answer;
 * hand out nothing.
 */
export type SessionJoinOutcome =
	| { readonly outcome: "joined" }
	| { readonly outcome: "refused" }
	| { readonly outcome: "unavailable" };

/**
 * `done`: the session is closed and every item of its close work ran.
 * `pending`: the closing commit has landed — no liveness read answers `live`
 * from it on and nothing joins — while work is still outstanding; a later
 * close of the session or the sweep resumes it. Both carry the relying
 * parties (`client_id`) and federations the session joined: the call that
 * made the closing commit answers, while the per-session stores are read
 * elsewhere, those they listed first, then the snapshot's, each once — the
 * federations in the order they joined; a later call answers the snapshot's.
 * `unavailable`: the closing commit did not land, or whether it did could
 * not be read; or, where the commit found no live record (the session's end
 * passed on the store's clock), an item of the close work, run with no
 * record to save it in, failed.
 */
export type SessionCloseOutcome =
	| {
			readonly outcome: "done" | "pending";
			readonly rps: readonly string[];
			readonly federations: readonly string[];
	  }
	| { readonly outcome: "unavailable" };

/**
 * `listed`: the federations a session joined, in the order they joined:
 * while the per-session stores are read elsewhere, those of their index in
 * the order they were added (every join writes the index before the record),
 * then the record's, each once — the union and order the close that makes the
 * closing commit answers. `unavailable`: a store could not answer.
 */
export type SessionFederations =
	| { readonly outcome: "listed"; readonly federations: readonly string[] }
	| { readonly outcome: "unavailable" };

/** `live`, with the user session; `not_live` from the closing commit on, or once the user session is gone. */
export type SessionLiveness =
	| { readonly outcome: "live"; readonly session: UserSession }
	| { readonly outcome: "not_live" }
	| { readonly outcome: "unavailable" };

/** How many closing sessions one resumption left `done`, still `pending`, or could not read. */
export interface SessionResumeReport {
	readonly done: number;
	readonly pending: number;
	readonly unavailable: number;
}

/** The session lifecycle, filled in the `sessionLifecycle` slot. */
export interface SessionLifecycle {
	/** Opens the lifecycle of the session `sid` as it is established. Idempotent for the same subject and end. */
	open(sid: string, request: SessionOpenRequest): Promise<SessionOpenOutcome>;
	/** Adds what `request` names to the live session `sid`, only while it is not closing. */
	join(sid: string, request: SessionJoinRequest): Promise<SessionJoinOutcome>;
	/** Closes `sid` for `cause` (the first close's cause is kept), and runs or resumes its close work. */
	close(sid: string, cause: SessionCloseCause): Promise<SessionCloseOutcome>;
	/** Whether `sid` is live: `not_live` for a sid the port cannot hold, which names no session. */
	liveness(sid: string): Promise<SessionLiveness>;
	/**
	 * The federations `sid` joined, before it is closed: what a logout reads to
	 * end the first one upstream with the tokens a close removes. None for a
	 * sid the port cannot hold, which names no session.
	 */
	federations(sid: string): Promise<SessionFederations>;
	/** Runs the close work of every closing session. Rejects when the closing listing cannot be read. */
	resumePending(): Promise<SessionResumeReport>;
}

export interface SessionLifecycleOptions {
	readonly store: SessionLifecycleStore;
	readonly userSessionStore: UserSessionStore;
	readonly refreshTokenFamilyRevocation: RefreshTokenFamilyRevocation;
	readonly federationTokenStore: FederationTokenStore;
	/** Absent: a close removes no subject index entry. */
	readonly subjectSessionIndex?: SubjectSessionIndex;
	/**
	 * How to read the notifier when a close runs: at the closing commit and
	 * when it tells. Absent, or answering `undefined`: a close tells no relying
	 * party.
	 */
	readonly notifier?: () => SessionCloseNotifier | undefined;
	/** The per-session stores written beside the lifecycle record. */
	readonly sessionRPRegistry: SessionRPRegistry;
	readonly sessionFamilyIndex: SessionFamilyIndex;
	readonly sessionFederationIndex: SessionFederationIndex;
	/**
	 * How long a closing record is kept from its closing commit, in whole
	 * milliseconds from 0 to a year: the longest refresh-token lifetime, so
	 * pending close work outlives every token it revokes.
	 */
	readonly retainMs: number;
	/** Defaults to `consoleLogger`. */
	readonly logger?: EventLogger;
}

/** The session-wide close work items. */
const REVOKE_BRIDGED_FAMILIES = "revoke_bridged_families";
const NOTIFY_BRIDGED_RPS = "notify_bridged_rps";
const REMOVE_FEDERATION_TOKENS = "remove_federation_tokens";
const REMOVE_SUBJECT_SESSION = "remove_subject_session";
const REMOVE_SESSION_INDEXES = "remove_session_indexes";
const DELETE_USER_SESSION = "delete_user_session";

const FAMILY_ITEM = sessionCloseItemOf({ kind: "family", id: "" });
const RP_ITEM = sessionCloseItemOf({ kind: "rp", id: "" });

/**
 * What each cause runs beyond the work every close runs (revoke the
 * families, remove the federation tokens and the per-session indexes,
 * delete the user session, and remove the subject's entry last): whether it
 * tells the relying parties, those of the record and those of the
 * per-session stores.
 */
const CLOSE_POLICY: Readonly<Record<SessionCloseCause, { readonly tellsRelyingParties: boolean }>> =
	Object.freeze({
		rp_logout: { tellsRelyingParties: true },
		session_logout: { tellsRelyingParties: true },
		subject_revocation: { tellsRelyingParties: true },
		operator_reset: { tellsRelyingParties: true },
		// A session that ran out ends silently, as natural expiry always has.
		expiry: { tellsRelyingParties: false },
	});

/**
 * The phase an item runs in. An item runs only once no item of an earlier
 * phase is pending in the record, so a later phase never runs over work an
 * earlier one has not durably done: revocations and removals first, then
 * the relying parties (and an item this code does not know), then the
 * per-session indexes the bridge steps read, then the user session, and the
 * subject's index entry last: a close still pending keeps the sid where a
 * subject-wide revocation enumerates it, so where subject revocation closes
 * through the lifecycle a retry of that revocation finds the sid and
 * resumes its close.
 */
const phaseOf = (item: string): number => {
	if (
		item.startsWith(FAMILY_ITEM) ||
		item === REVOKE_BRIDGED_FAMILIES ||
		item === REMOVE_FEDERATION_TOKENS
	) {
		return 0;
	}
	if (item === REMOVE_SESSION_INDEXES) return 2;
	if (item === DELETE_USER_SESSION) return 3;
	if (item === REMOVE_SUBJECT_SESSION) return 4;
	return 1;
};

/** The items to run next: those of the earliest phase still pending, not given up on in this run. */
const nextItems = (pending: readonly string[], skipped: ReadonlySet<string>): string[] => {
	const earliest = Math.min(...pending.map(phaseOf));
	return pending.filter((item) => phaseOf(item) === earliest && !skipped.has(item));
};

/**
 * How many notices and family revocations one close run makes at once,
 * whether they come from the record's participants or from the per-session
 * stores: a notice waits on its relying party, so a close tells several in
 * the time of the slowest rather than of all of them together.
 */
const CLOSE_CONCURRENCY = 8;

/** Runs a call once fewer than `places` calls it was handed are running, holding a place until it settles. */
type CallLimit = <T>(call: () => Promise<T>) => Promise<T>;

const callLimit = (places: number): CallLimit => {
	let free = places;
	const waiting: (() => void)[] = [];
	return async (call) => {
		if (free > 0) free -= 1;
		else await new Promise<void>((resolve) => waiting.push(resolve));
		try {
			return await call();
		} finally {
			const next = waiting.shift();
			if (next === undefined) free += 1;
			else next();
		}
	};
};

/** Runs `run` for every one of `items` at once; settles once every run has, rejecting with the first failure. */
const eachSettled = async <T,>(
	items: readonly T[],
	run: (item: T) => Promise<void>,
): Promise<void> => {
	const failed = (await Promise.allSettled(items.map(run))).find(
		(result) => result.status === "rejected",
	);
	if (failed !== undefined) throw failed.reason;
};

/** `record` with `item` recorded done, closed once nothing is pending. */
const withoutItem = (record: SessionLifecycleRecord, item: string): SessionLifecycleRecord => {
	const close = record.close;
	if (close === undefined) return record;
	const pending = close.pending.filter((candidate) => candidate !== item);
	return {
		...record,
		state: pending.length === 0 ? "closed" : "closing",
		close: { ...close, pending },
	};
};

const idsOf = (record: SessionLifecycleRecord, kind: SessionParticipantKind): string[] =>
	record.participants.filter((p) => p.kind === kind).map((p) => p.id);

/** The participants `request` names, each as the port admits it; a RangeError otherwise. */
const participantsOf = (request: SessionJoinRequest): SessionParticipant[] => {
	const participants: SessionParticipant[] = [];
	const add = (kind: SessionParticipantKind, id: string | undefined): void => {
		if (id !== undefined) participants.push(checkSessionParticipant({ kind, id, data: "" }));
	};
	add("rp", request.rp?.clientId);
	add("family", request.familyId);
	add("federation", request.federation);
	if (participants.length === 0) {
		throw new RangeError(
			"session lifecycle: a join names a relying party, a family or a federation",
		);
	}
	return participants;
};

/** The most sids one page of the closing listing asks for. */
const RESUME_PAGE = 100;

export function createSessionLifecycle(options: SessionLifecycleOptions): SessionLifecycle {
	const {
		store,
		userSessionStore,
		refreshTokenFamilyRevocation,
		federationTokenStore,
		subjectSessionIndex,
		retainMs,
	} = options;
	if (!Number.isInteger(retainMs) || retainMs < 0 || retainMs > MAX_DURATION_MS) {
		throw new RangeError(
			`createSessionLifecycle: retainMs must be a whole number of milliseconds from 0 to ${MAX_DURATION_MS} (got ${String(retainMs)})`,
		);
	}
	const logger = options.logger ?? consoleLogger;
	const notifierNow = options.notifier ?? ((): SessionCloseNotifier | undefined => undefined);
	const bridge = createSessionStoresBridge(options);

	const requestFor = (cause: SessionCloseCause): SessionCloseRequest => {
		const tells = CLOSE_POLICY[cause].tellsRelyingParties && notifierNow() !== undefined;
		return {
			cause,
			steps: [
				REVOKE_BRIDGED_FAMILIES,
				REMOVE_FEDERATION_TOKENS,
				...(tells ? [NOTIFY_BRIDGED_RPS] : []),
				REMOVE_SESSION_INDEXES,
				DELETE_USER_SESSION,
				...(subjectSessionIndex === undefined ? [] : [REMOVE_SUBJECT_SESSION]),
			],
			perParticipant: tells ? ["family", "rp"] : ["family"],
			retainMs,
		};
	};

	/**
	 * The service's one read of a user session, through admission's one read
	 * of a session record: liveness answers it, and a join or a close reads
	 * its subject and end from it.
	 */
	const userSessionOf = async (sid: string): Promise<UserSession | null> =>
		(await readRecord(userSessionStore, sid)) ?? null;

	const unavailable = (operation: string, sid: string, error: unknown): void => {
		logger.warn({ operation, sid, err: loggableError(error) }, "session_lifecycle_unavailable");
	};

	/** Tells relying party `clientId` that the closing `record` closed. */
	const tell = (sid: string, record: SessionLifecycleRecord, clientId: string): Promise<void> => {
		const notifier = notifierNow();
		if (notifier === undefined) throw new Error("no sessionCloseNotifier is wired");
		const cause = record.close?.cause;
		if (cause === undefined) throw new Error("the record holds no close");
		return notifier.notify({ sid, sub: record.sub, clientId, cause });
	};

	/**
	 * The work `item` names, for the closing `record`: its notices and family
	 * revocations each wait for a place in `limit`, and nothing else does.
	 */
	const work = async (
		sid: string,
		record: SessionLifecycleRecord,
		item: string,
		limit: CallLimit,
	): Promise<void> => {
		const revoke = (familyId: string) =>
			limit(() => refreshTokenFamilyRevocation.revokeFamily(familyId));
		const notify = (clientId: string) => limit(() => tell(sid, record, clientId));
		if (item.startsWith(FAMILY_ITEM)) return revoke(item.slice(FAMILY_ITEM.length));
		if (item.startsWith(RP_ITEM)) return notify(item.slice(RP_ITEM.length));
		switch (item) {
			case REVOKE_BRIDGED_FAMILIES: {
				// What the old stores hold now: entries lapsed at the session's end are not revoked here.
				// The record's own participants have items of their own.
				const own = new Set(idsOf(record, "family"));
				const families = await bridge.families(sid, record.expiresAt);
				return eachSettled(
					families.filter((familyId) => !own.has(familyId)),
					revoke,
				);
			}
			case NOTIFY_BRIDGED_RPS: {
				const own = new Set(idsOf(record, "rp"));
				const relyingParties = await bridge.relyingParties(sid);
				return eachSettled(
					relyingParties.filter((clientId) => !own.has(clientId)),
					notify,
				);
			}
			case REMOVE_FEDERATION_TOKENS:
				return federationTokenStore.removeBySid(sid);
			case REMOVE_SUBJECT_SESSION:
				if (subjectSessionIndex === undefined) throw new Error("no subjectSessionIndex is wired");
				return subjectSessionIndex.removeSid(record.sub, sid);
			case REMOVE_SESSION_INDEXES:
				return bridge.remove(sid);
			case DELETE_USER_SESSION:
				return userSessionStore.delete(sid);
		}
		throw new Error(`no work is known for ${item}`);
	};

	const ran = async (
		sid: string,
		record: SessionLifecycleRecord,
		item: string,
		limit: CallLimit,
	): Promise<boolean> => {
		try {
			await work(sid, record, item, limit);
			return true;
		} catch (error) {
			logger.warn({ sid, item, err: loggableError(error) }, "session_close_item_failed");
			return false;
		}
	};

	/**
	 * Runs and records the pending items of the closing record `start`, until
	 * it is closed or nothing is left that this run has not seen fail: the
	 * items of the earliest phase pending run together, their notices and
	 * revocations sharing the run's `CLOSE_CONCURRENCY` places, then each item
	 * that ran is recorded, one at a time, at the generation read.
	 */
	const finish = async (
		sid: string,
		start: Versioned<SessionLifecycleRecord>,
	): Promise<"done" | "pending"> => {
		let record = start.value;
		let generation = start.generation;
		/** Items this run did that are not yet recorded. */
		const done = new Set<string>();
		/** Items this run gave up on: their work, or recording it, failed. They stay pending. */
		const skipped = new Set<string>();
		// Each conflict means another run recorded an item, so there are no
		// more conflicts than items.
		let conflictsLeft = start.value.close?.pending.length ?? 0;
		const limit = callLimit(CLOSE_CONCURRENCY);
		while (record.state === "closing") {
			const pending = record.close?.pending ?? [];
			const item = pending.find((candidate) => done.has(candidate));
			if (item === undefined) {
				const batch = nextItems(pending, skipped);
				if (batch.length === 0) return "pending";
				const closing = record;
				await eachSettled(batch, async (each) => {
					if (await ran(sid, closing, each, limit)) done.add(each);
					else skipped.add(each);
				});
				continue;
			}
			let answer: ConditionalReplaceAnswer;
			try {
				answer = readConditionalReplaceAnswer(await store.completeIf(sid, generation, item));
			} catch (error) {
				// Still pending: a later run does it again. The other items of its
				// phase go on.
				unavailable("complete", sid, error);
				done.delete(item);
				skipped.add(item);
				continue;
			}
			if (answer.outcome === "updated") {
				done.delete(item);
				generation = answer.generation;
				record = withoutItem(record, item);
				continue;
			}
			if (answer.outcome === "missing" || conflictsLeft === 0) return "pending";
			conflictsLeft -= 1;
			let reread: Versioned<SessionLifecycleRecord> | null;
			try {
				reread = readVersionedSessionLifecycle(await store.read(sid));
			} catch (error) {
				unavailable("read", sid, error);
				return "pending";
			}
			if (reread === null) return "pending";
			record = reread.value;
			generation = reread.generation;
		}
		return "done";
	};

	/**
	 * The closing commit of a record not yet closing (`record`, or none): the
	 * per-session stores' end mark first, an absent record adopted from the
	 * user session, then the commit. What joined through the per-session
	 * stores is not imported: the bridge steps read those stores when they
	 * run. Answers the record, committed (`closing`) or not, and what the
	 * per-session stores listed after the mark; `null` when there is neither a
	 * record nor a user session to close.
	 *
	 * A commit that finds no live record — the session's end has passed on
	 * the store's clock, before its record could be opened or since it was
	 * read — has no record to save the work in, so the work runs here, in its
	 * phases, over the record the commit would have saved: the read record's
	 * participants, or none. Any item that fails throws, and the close
	 * answers `unavailable`; a later close runs it all again.
	 */
	const begin = async (
		sid: string,
		cause: SessionCloseCause,
		record: SessionLifecycleRecord | undefined,
	): Promise<{
		readonly closing?: Versioned<SessionLifecycleRecord>;
		readonly record: SessionLifecycleRecord;
		readonly bridged: BridgedClose;
	} | null> => {
		let end: { readonly sub: string; readonly expiresAt: Date } | undefined = record;
		if (end === undefined) {
			const session = await userSessionOf(sid);
			if (session === null) return null;
			end = { sub: session.sub, expiresAt: session.expiresAt };
		}
		const bridged = await bridge.close(sid, end.expiresAt);
		if (record === undefined) readSessionOpenAnswer(await store.open(sid, end.sub, end.expiresAt));
		const request = requestFor(cause);
		const answer = readSessionCloseAnswer(await store.beginClose(sid, request));
		if (answer.outcome !== "missing") {
			const closing = { value: answer.record, generation: answer.generation };
			return { closing, record: answer.record, bridged };
		}
		const participants = record?.participants ?? [];
		const unsaved: SessionLifecycleRecord = {
			sub: end.sub,
			state: "closing",
			expiresAt: end.expiresAt,
			participants,
			close: {
				cause,
				closingAt: new Date(),
				pending: [
					...request.steps,
					...participants
						.filter((p) => request.perParticipant.includes(p.kind))
						.map(sessionCloseItemOf),
				],
			},
		};
		await runUnsaved(sid, unsaved);
		return { record: unsaved, bridged };
	};

	/**
	 * Runs the work of `record`, which no store holds, in its phases: each
	 * phase only once every item of the earlier ones has run. Throws when an
	 * item fails, leaving the later phases unrun.
	 */
	const runUnsaved = async (sid: string, record: SessionLifecycleRecord): Promise<void> => {
		const limit = callLimit(CLOSE_CONCURRENCY);
		let pending = record.close?.pending ?? [];
		while (pending.length > 0) {
			const batch = nextItems(pending, new Set());
			const failed: string[] = [];
			await eachSettled(batch, async (item) => {
				if (!(await ran(sid, record, item, limit))) failed.push(item);
			});
			if (failed.length > 0) {
				throw new Error(
					`the close work of a session with no lifecycle record failed at ${failed.join(", ")}`,
				);
			}
			pending = pending.filter((item) => !batch.includes(item));
		}
	};

	/** Whether everything `request` names joined `sid`; written beside the per-session stores. */
	const joins = async (
		sid: string,
		request: SessionJoinRequest,
		participants: readonly SessionParticipant[],
	): Promise<boolean> => {
		const read = readVersionedSessionLifecycle(await store.read(sid));
		// A record that exists is not compared with the user session's subject:
		// the caller admitted the session first, and admission refuses a claim
		// whose subject is not the record's.
		if (read !== null && read.value.state !== "active") return false;
		const session = await userSessionOf(sid);
		if (session === null) return false;
		if ((await bridge.join(sid, request, session.expiresAt, read === null)) === "refused") {
			return false;
		}
		if (read === null) readSessionOpenAnswer(await store.open(sid, session.sub, session.expiresAt));
		for (const participant of participants) {
			if (readSessionJoinAnswer(await store.join(sid, participant)).outcome !== "joined") {
				return false;
			}
		}
		// Adopting, the join opened the record itself: a close that completed
		// since the read above, and whose closed record then left the store,
		// let the open land. The close deletes the user session before it
		// closes the record, so a session still read now was never closed.
		if (read === null && (await userSessionOf(sid)) === null) return false;
		return true;
	};

	/** Takes back what a refused join was handed; logged, never thrown. */
	const withdraw = async (sid: string, request: SessionJoinRequest): Promise<void> => {
		if (request.familyId !== undefined) {
			await refreshTokenFamilyRevocation.revokeFamily(request.familyId).catch((error: unknown) => {
				logger.warn(
					{ operation: "revoke_family", sid, err: loggableError(error) },
					"session_join_withdraw_failed",
				);
			});
		}
		if (request.federation !== undefined) {
			await federationTokenStore.delete(sid, request.federation).catch((error: unknown) => {
				logger.warn(
					{ operation: "remove_federation_tokens", sid, err: loggableError(error) },
					"session_join_withdraw_failed",
				);
			});
		}
	};

	return {
		async open(sid, { sub, expiresAt }) {
			checkSessionLifecycleKey(sid, "sid");
			checkSessionLifecycleKey(sub, "sub");
			const end = checkSessionExpiresAt(expiresAt);
			try {
				return readSessionOpenAnswer(await store.open(sid, sub, end));
			} catch (error) {
				unavailable("open", sid, error);
				return { outcome: "unavailable" };
			}
		},

		async join(sid, request) {
			checkSessionLifecycleKey(sid, "sid");
			const participants = participantsOf(request);
			let joined: boolean;
			try {
				joined = await joins(sid, request, participants);
			} catch (error) {
				unavailable("join", sid, error);
				return { outcome: "unavailable" };
			}
			if (joined) return { outcome: "joined" };
			await withdraw(sid, request);
			return { outcome: "refused" };
		},

		async close(sid, cause) {
			checkSessionLifecycleKey(sid, "sid");
			if (!(SESSION_CLOSE_CAUSES as readonly unknown[]).includes(cause)) {
				throw new RangeError(
					`session lifecycle: cause must be one of ${SESSION_CLOSE_CAUSES.join(", ")}`,
				);
			}
			// The committed record, whose work `finish` runs and records; absent
			// when the work already ran with no record to save it in.
			let closing: Versioned<SessionLifecycleRecord> | undefined;
			let record: SessionLifecycleRecord;
			let bridged: BridgedClose = { rps: [], federations: [] };
			try {
				const read = readVersionedSessionLifecycle(await store.read(sid));
				if (read !== null && read.value.state !== "active") {
					closing = read;
					record = read.value;
				} else {
					const begun = await begin(sid, cause, read?.value);
					if (begun === null) return { outcome: "done", rps: [], federations: [] };
					({ closing, record, bridged } = begun);
				}
			} catch (error) {
				unavailable("close", sid, error);
				return { outcome: "unavailable" };
			}
			const outcome =
				closing === undefined || closing.value.state === "closed"
					? "done"
					: await finish(sid, closing);
			// What the per-session stores listed first: every join writes them
			// before the record, so their order is the order of joining.
			const union = (own: readonly string[], listed: readonly string[]): string[] => [
				...new Set([...listed, ...own]),
			];
			return {
				outcome,
				rps: union(idsOf(record, "rp"), bridged.rps),
				federations: union(idsOf(record, "federation"), bridged.federations),
			};
		},

		async federations(sid) {
			// A sid the port cannot hold names no session; only a write refuses it.
			if (!isSessionLifecycleKey(sid)) return { outcome: "listed", federations: [] };
			try {
				const read = readVersionedSessionLifecycle(await store.read(sid));
				const own = read === null ? [] : idsOf(read.value, "federation");
				// The index first: every join writes it before the record.
				return {
					outcome: "listed",
					federations: [...new Set([...(await bridge.federations(sid)), ...own])],
				};
			} catch (error) {
				unavailable("federations", sid, error);
				return { outcome: "unavailable" };
			}
		},

		async liveness(sid) {
			// A sid the port cannot hold names no session; only a write refuses it.
			if (!isSessionLifecycleKey(sid)) return { outcome: "not_live" };
			try {
				const read = readVersionedSessionLifecycle(await store.read(sid));
				// A logout through the per-session stores alone leaves a record
				// active until it lapses; such a session is not live once its user
				// session is deleted, which the read below answers.
				if (read !== null && read.value.state !== "active") return { outcome: "not_live" };
				const session = await userSessionOf(sid);
				return session === null ? { outcome: "not_live" } : { outcome: "live", session };
			} catch (error) {
				unavailable("liveness", sid, error);
				return { outcome: "unavailable" };
			}
		},

		async resumePending() {
			let done = 0;
			let pending = 0;
			let unread = 0;
			let after = "";
			for (;;) {
				const sids = readSessionLifecycleListing(
					await store.listClosing(RESUME_PAGE, after),
					RESUME_PAGE,
					after,
				);
				for (const sid of sids) {
					let read: Versioned<SessionLifecycleRecord> | null;
					try {
						read = readVersionedSessionLifecycle(await store.read(sid));
					} catch (error) {
						unavailable("resume", sid, error);
						unread += 1;
						continue;
					}
					if (read === null || read.value.state !== "closing") done += 1;
					else if ((await finish(sid, read)) === "done") done += 1;
					else pending += 1;
				}
				const last = sids.at(-1);
				if (sids.length < RESUME_PAGE || last === undefined) {
					return { done, pending, unavailable: unread };
				}
				after = last;
			}
		},
	};
}

// ComponentMap declaration-merge: an optional slot, filled by
// `sessionLifecycleModule`.
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly sessionLifecycle?: SessionLifecycle;
	}
}
