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
 * The session lifecycle service, the one caller of `SessionLifecycleStore`:
 * joins a session, closes it and runs the close work, says whether it is
 * live, and resumes closes left pending. Its callers see `joined` /
 * `refused`, `done` / `pending`, `live` / `not_live` and `unavailable`;
 * generations, states, work items, the cause policy and the bridge to the
 * per-session stores stay here.
 *
 * A close commits first and then runs its work. Every item is safe to run
 * more than once and is recorded at the generation read, so two closes of one
 * session and the sweep may overlap. The user session is deleted last, once
 * every other item is recorded; a failed item keeps the record closing.
 */

import {
	type ConditionalReplaceAnswer,
	readConditionalReplaceAnswer,
	type Versioned,
} from "../../adapters/conditionalWrite.mjs";
import { MAX_DURATION_MS } from "../../config/durations.mjs";
import type { FederationTokenStore } from "../../federation-tokens/types.mjs";
import { consoleLogger } from "../../logging/consoleLogger.mjs";
import type { EventLogger } from "../../logging/Logger.mjs";
import { loggableError } from "../../logging/loggableError.mjs";
import type { RefreshTokenFamilyRevocation } from "../../refresh-token-family/types.mjs";
import type {
	RegisteredRP,
	SessionFamilyIndex,
	SessionFederationIndex,
	SessionRPRegistry,
	SubjectSessionIndex,
	UserSession,
	UserSessionStore,
} from "../types.mjs";
import { createSessionStoresBridge } from "./bridge.mjs";
import type { SessionCloseNotifier } from "./notifier.mjs";
import {
	checkSessionLifecycleKey,
	checkSessionParticipant,
	readSessionCloseAnswer,
	readSessionJoinAnswer,
	readSessionLifecycleListing,
	readSessionOpenAnswer,
	readVersionedSessionLifecycle,
} from "./readers.mjs";
import {
	SESSION_CLOSE_CAUSES,
	type SessionCloseCause,
	type SessionCloseRequest,
	type SessionLifecycleRecord,
	type SessionLifecycleStore,
	type SessionParticipant,
	type SessionParticipantKind,
	sessionCloseItemOf,
} from "./types.mjs";

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
 * parties (`client_id`) and federations of the snapshot, in no promised
 * order. `unavailable`: the closing commit did not land, or whether it did
 * could not be read.
 */
export type SessionCloseOutcome =
	| {
			readonly outcome: "done" | "pending";
			readonly rps: readonly string[];
			readonly federations: readonly string[];
	  }
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
	/** Adds what `request` names to the live session `sid`, only while it is not closing. */
	join(sid: string, request: SessionJoinRequest): Promise<SessionJoinOutcome>;
	/** Closes `sid` for `cause` (the first close's cause is kept), and runs or resumes its close work. */
	close(sid: string, cause: SessionCloseCause): Promise<SessionCloseOutcome>;
	/** Whether `sid` is live. */
	liveness(sid: string): Promise<SessionLiveness>;
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
	/** Absent: a close tells no relying party. */
	readonly notifier?: SessionCloseNotifier;
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
const REMOVE_FEDERATION_TOKENS = "remove_federation_tokens";
const REMOVE_SUBJECT_SESSION = "remove_subject_session";
const REMOVE_SESSION_INDEXES = "remove_session_indexes";
const DELETE_USER_SESSION = "delete_user_session";

const FAMILY_ITEM = sessionCloseItemOf({ kind: "family", id: "" });
const RP_ITEM = sessionCloseItemOf({ kind: "rp", id: "" });

/**
 * What each cause runs beyond the work every close runs (revoke the
 * families, remove the federation tokens, the subject's entry and the
 * per-session indexes, delete the user session): whether it tells the
 * relying parties.
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
 * The order items run in: the families first, so no refresh outlives the
 * close; the relying parties after the provider's own state; an item this
 * code does not know after those; the user session's delete last.
 */
const rankOf = (item: string): number => {
	if (item.startsWith(FAMILY_ITEM)) return 0;
	if (item === REMOVE_FEDERATION_TOKENS) return 1;
	if (item === REMOVE_SUBJECT_SESSION) return 2;
	if (item.startsWith(RP_ITEM)) return 3;
	if (item === REMOVE_SESSION_INDEXES) return 4;
	if (item === DELETE_USER_SESSION) return 6;
	return 5;
};

/** The next item to run: not failed in this run, and the user session's delete only once nothing else is pending. */
const nextItem = (pending: readonly string[], failed: ReadonlySet<string>): string | undefined => {
	let next: string | undefined;
	for (const item of pending) {
		if (failed.has(item)) continue;
		if (item === DELETE_USER_SESSION && pending.length > 1) continue;
		if (next === undefined || rankOf(item) < rankOf(next)) next = item;
	}
	return next;
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
		notifier,
		retainMs,
	} = options;
	if (!Number.isInteger(retainMs) || retainMs < 0 || retainMs > MAX_DURATION_MS) {
		throw new RangeError(
			`createSessionLifecycle: retainMs must be a whole number of milliseconds from 0 to ${MAX_DURATION_MS} (got ${String(retainMs)})`,
		);
	}
	const logger = options.logger ?? consoleLogger;
	const bridge = createSessionStoresBridge(options);

	const steps = [
		REMOVE_FEDERATION_TOKENS,
		...(subjectSessionIndex === undefined ? [] : [REMOVE_SUBJECT_SESSION]),
		REMOVE_SESSION_INDEXES,
		DELETE_USER_SESSION,
	];
	const requestFor = (cause: SessionCloseCause): SessionCloseRequest => ({
		cause,
		steps,
		perParticipant:
			CLOSE_POLICY[cause].tellsRelyingParties && notifier !== undefined
				? ["family", "rp"]
				: ["family"],
		retainMs,
	});

	/**
	 * The service's one read of a user session: liveness answers it, and a
	 * join or a close reads its subject and end from it.
	 */
	const userSessionOf = (sid: string): Promise<UserSession | null> => userSessionStore.get(sid);

	const unavailable = (operation: string, sid: string, error: unknown): void => {
		logger.warn({ operation, sid, err: loggableError(error) }, "session_lifecycle_unavailable");
	};

	/** The work `item` names, for the closing `record`. */
	const work = async (sid: string, record: SessionLifecycleRecord, item: string): Promise<void> => {
		if (item.startsWith(FAMILY_ITEM)) {
			return refreshTokenFamilyRevocation.revokeFamily(item.slice(FAMILY_ITEM.length));
		}
		if (item.startsWith(RP_ITEM)) {
			if (notifier === undefined) throw new Error("no sessionCloseNotifier is wired");
			const cause = record.close?.cause;
			if (cause === undefined) throw new Error("the record holds no close");
			return notifier.notify({ sid, sub: record.sub, clientId: item.slice(RP_ITEM.length), cause });
		}
		switch (item) {
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
	): Promise<boolean> => {
		try {
			await work(sid, record, item);
			return true;
		} catch (error) {
			logger.warn({ sid, item, err: loggableError(error) }, "session_close_item_failed");
			return false;
		}
	};

	/**
	 * Runs and records the pending items of the closing record `start`, until
	 * it is closed or nothing is left that this run has not seen fail.
	 */
	const finish = async (
		sid: string,
		start: Versioned<SessionLifecycleRecord>,
	): Promise<"done" | "pending"> => {
		let record = start.value;
		let generation = start.generation;
		/** Items this run did that are not yet recorded. */
		const done = new Set<string>();
		const failed = new Set<string>();
		// Each conflict means another run recorded an item, so there are no
		// more conflicts than items.
		let conflictsLeft = start.value.close?.pending.length ?? 0;
		while (record.state === "closing") {
			const pending = record.close?.pending ?? [];
			const unrecorded = pending.find((item) => done.has(item));
			const item = unrecorded ?? nextItem(pending, failed);
			if (item === undefined) return "pending";
			if (unrecorded === undefined) {
				if (!(await ran(sid, record, item))) {
					failed.add(item);
					continue;
				}
				done.add(item);
			}
			let answer: ConditionalReplaceAnswer;
			try {
				answer = readConditionalReplaceAnswer(await store.completeIf(sid, generation, item));
			} catch (error) {
				unavailable("complete", sid, error);
				return "pending";
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
	 * per-session stores' end mark first, what joined through them added, an
	 * absent record adopted from the user session, then the commit. `null`
	 * when there is neither a record nor a user session to close.
	 */
	const begin = async (
		sid: string,
		cause: SessionCloseCause,
		record: SessionLifecycleRecord | undefined,
	): Promise<Versioned<SessionLifecycleRecord> | null> => {
		let end: { readonly sub: string; readonly expiresAt: Date } | undefined = record;
		if (end === undefined) {
			const session = await userSessionOf(sid);
			if (session === null) return null;
			end = { sub: session.sub, expiresAt: session.expiresAt };
		}
		const joinedBefore = await bridge.close(sid, end.expiresAt);
		if (record === undefined) readSessionOpenAnswer(await store.open(sid, end.sub, end.expiresAt));
		for (const participant of joinedBefore) {
			if (readSessionJoinAnswer(await store.join(sid, participant)).outcome !== "joined") break;
		}
		const answer = readSessionCloseAnswer(await store.beginClose(sid, requestFor(cause)));
		if (answer.outcome === "missing") {
			throw new Error(
				"no lifecycle record to close: the session's end has passed on the store's clock",
			);
		}
		return { value: answer.record, generation: answer.generation };
	};

	/** Whether everything `request` names joined `sid`; written beside the per-session stores. */
	const joins = async (
		sid: string,
		request: SessionJoinRequest,
		participants: readonly SessionParticipant[],
	): Promise<boolean> => {
		const read = readVersionedSessionLifecycle(await store.read(sid));
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
			let closing: Versioned<SessionLifecycleRecord>;
			try {
				const read = readVersionedSessionLifecycle(await store.read(sid));
				const begun =
					read !== null && read.value.state !== "active"
						? read
						: await begin(sid, cause, read?.value);
				if (begun === null) return { outcome: "done", rps: [], federations: [] };
				closing = begun;
			} catch (error) {
				unavailable("close", sid, error);
				return { outcome: "unavailable" };
			}
			const outcome = closing.value.state === "closed" ? "done" : await finish(sid, closing);
			return {
				outcome,
				rps: idsOf(closing.value, "rp"),
				federations: idsOf(closing.value, "federation"),
			};
		},

		async liveness(sid) {
			checkSessionLifecycleKey(sid, "sid");
			try {
				const read = readVersionedSessionLifecycle(await store.read(sid));
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
