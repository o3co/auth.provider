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
 * The one reading of what a `SessionLifecycleStore` answers, and of what a
 * caller hands one. A reader reads each property once and answers a fresh
 * frozen copy; anything outside the port's types is a TypeError naming the
 * field, which the caller treats as the store's outage. A check refuses a
 * caller's input outside the port's rules with a RangeError.
 */

import {
	copyItems,
	field,
	generationOf,
	outcomeOf,
	readVersioned,
	type StoreGeneration,
	type Versioned,
} from "../../adapters/conditionalWrite.mjs";
import { MAX_DURATION_MS } from "../../config/durations.mjs";
import {
	SESSION_CLOSE_CAUSES,
	SESSION_LIFECYCLE_MAX_KEY_LENGTH,
	SESSION_LIFECYCLE_MAX_LISTING,
	SESSION_LIFECYCLE_STATES,
	SESSION_PARTICIPANT_KINDS,
	SESSION_PARTICIPANT_MAX_DATA_LENGTH,
	type SessionClose,
	type SessionCloseAnswer,
	type SessionCloseRequest,
	type SessionJoinAnswer,
	type SessionLifecycleRecord,
	type SessionOpenAnswer,
	type SessionParticipant,
	sessionCloseItemOf,
} from "./types.mjs";

/** A step name: 1 to 64 of `a`–`z`, `0`–`9` and `_`, a letter first. */
const STEP_NAME = /^[a-z][a-z0-9_]{0,63}$/;

/** A lone surrogate: it has no UTF-8 of its own, so two keys holding one could share their bytes. */
const LONE_SURROGATE = /\p{Cs}/u;

/** 1 to 512 characters of well-formed UTF-16, so that its UTF-8 bytes name it alone. */
const isKey = (value: unknown): value is string =>
	typeof value === "string" &&
	value.length > 0 &&
	value.length <= SESSION_LIFECYCLE_MAX_KEY_LENGTH &&
	!LONE_SURROGATE.test(value);

const isOneOf = <T extends string>(values: readonly T[], value: unknown): value is T =>
	(values as readonly unknown[]).includes(value);

/** Whether `value` names a work item: a step name, or a participant's kind, a colon and its id. */
const isCloseItem = (value: unknown): value is string => {
	if (typeof value !== "string") return false;
	if (STEP_NAME.test(value)) return true;
	const colon = value.indexOf(":");
	return (
		colon > 0 &&
		isOneOf(SESSION_PARTICIPANT_KINDS, value.slice(0, colon)) &&
		isKey(value.slice(colon + 1))
	);
};

/** The largest time a `Date` holds, in epoch milliseconds either way. */
const MAX_DATE_MS = 8.64e15;

/**
 * A `Date` with a valid time, copied from its own time value, never an
 * overridden `getTime`; `undefined` for anything else.
 */
const dateOf = (value: unknown): Date | undefined => {
	if (!(value instanceof Date)) return undefined;
	try {
		const time = Date.prototype.getTime.call(value);
		return Number.isFinite(time) && Math.abs(time) <= MAX_DATE_MS ? new Date(time) : undefined;
	} catch {
		return undefined;
	}
};

/** The order of a listing: by the sids' UTF-8 bytes, so every store can keep it. */
export const compareSessionSids = (a: string, b: string): number =>
	Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));

const isParticipantShape = (kind: unknown, id: unknown, data: unknown): boolean =>
	isOneOf(SESSION_PARTICIPANT_KINDS, kind) &&
	isKey(id) &&
	typeof data === "string" &&
	data.length <= SESSION_PARTICIPANT_MAX_DATA_LENGTH;

// ---------------------------------------------------------------------------
// Readers of a store's answers
// ---------------------------------------------------------------------------

const readParticipant = (value: unknown, what: string): SessionParticipant => {
	const kind = field(value, "kind", what);
	const id = field(value, "id", what);
	const data = field(value, "data", what);
	if (!isParticipantShape(kind, id, data)) throw new TypeError(`${what}: malformed`);
	return Object.freeze({ kind, id, data } as SessionParticipant);
};

/** `value` as an array copied once, its items read by `read`, none named twice by `keyOf`. */
const readList = <T,>(
	value: unknown,
	what: string,
	read: (item: unknown, what: string) => T,
	keyOf: (item: T) => string,
): readonly T[] => {
	if (!Array.isArray(value)) throw new TypeError(`${what}: not an array`);
	const items = copyItems(value as readonly unknown[], what).map((item) => read(item, what));
	if (new Set(items.map(keyOf)).size !== items.length)
		throw new TypeError(`${what}: an item is named twice`);
	return Object.freeze(items);
};

const readClose = (value: unknown, what: string): SessionClose => {
	const cause = field(value, "cause", what);
	if (!isOneOf(SESSION_CLOSE_CAUSES, cause)) throw new TypeError(`${what}: cause is malformed`);
	const closingAt = dateOf(field(value, "closingAt", what));
	if (closingAt === undefined) throw new TypeError(`${what}: closingAt is malformed`);
	const pending = readList(
		field(value, "pending", what),
		`${what}: pending`,
		(item, where) => {
			if (!isCloseItem(item)) throw new TypeError(`${where}: an item is malformed`);
			return item;
		},
		(item) => item,
	);
	return Object.freeze({ cause, closingAt, pending });
};

/** A lifecycle record, read once into a fresh frozen copy that shares nothing with `value`. */
const readRecord = (value: unknown, what: string): SessionLifecycleRecord => {
	const sub = field(value, "sub", what);
	if (!isKey(sub)) throw new TypeError(`${what}: sub is malformed`);
	const state = field(value, "state", what);
	if (!isOneOf(SESSION_LIFECYCLE_STATES, state)) throw new TypeError(`${what}: state is malformed`);
	const expiresAt = dateOf(field(value, "expiresAt", what));
	if (expiresAt === undefined) throw new TypeError(`${what}: expiresAt is malformed`);
	const participants = readList(
		field(value, "participants", what),
		`${what}: participants`,
		readParticipant,
		sessionCloseItemOf,
	);
	const rawClose = field(value, "close", what);
	let close: SessionClose | undefined;
	if (state === "active") {
		if (rawClose !== undefined) throw new TypeError(`${what}: an active record holds a close`);
	} else {
		close = readClose(rawClose, `${what}: close`);
		if ((state === "closing") !== close.pending.length > 0) {
			throw new TypeError(`${what}: pending work does not match the state`);
		}
	}
	return Object.freeze({ sub, state, expiresAt, participants, close });
};

/** A store's answer to `open`. */
export function readSessionOpenAnswer(answer: SessionOpenAnswer): SessionOpenAnswer {
	return Object.freeze({
		outcome: outcomeOf(answer, ["opened", "refused"], "session open answer"),
	});
}

/** A store's answer to `join`. */
export function readSessionJoinAnswer(answer: SessionJoinAnswer): SessionJoinAnswer {
	return Object.freeze({
		outcome: outcomeOf(answer, ["joined", "closed", "missing"], "session join answer"),
	});
}

/** A store's answer to `read`: `null` when it holds no live record, else the record and its generation. */
export function readVersionedSessionLifecycle(
	answer: Versioned<SessionLifecycleRecord> | null,
): Versioned<SessionLifecycleRecord> | null {
	const read = readVersioned(answer);
	if (read === null) return null;
	return Object.freeze({
		value: readRecord(read.value, "session lifecycle record"),
		generation: read.generation,
	});
}

/** A store's answer to `beginClose`: `missing`, or the record after the call, its state the outcome. */
export function readSessionCloseAnswer(answer: SessionCloseAnswer): SessionCloseAnswer {
	const what = "session close answer";
	const outcome = outcomeOf(answer, ["closing", "closed", "missing"], what);
	if (outcome === "missing") return Object.freeze({ outcome });
	const generation: StoreGeneration = generationOf(answer, what);
	const record = readRecord(field(answer, "record", what), `${what}: record`);
	if (record.state !== outcome)
		throw new TypeError(`${what}: the record's state is not the outcome`);
	return Object.freeze({ outcome, generation, record });
}

/**
 * A store's answer to `listClosing(limit, after)`: at most `limit` sids, in
 * ascending order of their UTF-8 bytes, each after `after`.
 */
export function readSessionLifecycleListing(
	answer: readonly string[],
	limit: number,
	after = "",
): readonly string[] {
	const what = "session closing listing";
	const sids = readList(
		answer,
		what,
		(item, where) => {
			if (!isKey(item)) throw new TypeError(`${where}: a sid is malformed`);
			return item;
		},
		(sid) => sid,
	);
	if (sids.length > limit) throw new TypeError(`${what}: more sids than the limit`);
	let previous = after;
	for (const sid of sids) {
		if (compareSessionSids(previous, sid) >= 0) {
			throw new TypeError(`${what}: sids are not in ascending order after the cursor`);
		}
		previous = sid;
	}
	return sids;
}

// ---------------------------------------------------------------------------
// Checks of a caller's input
// ---------------------------------------------------------------------------

/** `value[key]`, read once; a RangeError naming `what` when `value` is no object or the read throws. */
const inputField = (value: unknown, key: string, what: string): unknown => {
	try {
		return field(value, key, what);
	} catch {
		throw new RangeError(`${what}: ${key} could not be read`);
	}
};

/** A participant the port admits, as a frozen copy; a RangeError otherwise. */
export function checkSessionParticipant(participant: SessionParticipant): SessionParticipant {
	const what = "session participant";
	const kind = inputField(participant, "kind", what);
	const id = inputField(participant, "id", what);
	const data = inputField(participant, "data", what);
	if (!isParticipantShape(kind, id, data)) {
		throw new RangeError(
			`${what}: kind must be one of ${SESSION_PARTICIPANT_KINDS.join(", ")}, id 1 to ` +
				`${SESSION_LIFECYCLE_MAX_KEY_LENGTH} characters, and data a string of at most ` +
				`${SESSION_PARTICIPANT_MAX_DATA_LENGTH}`,
		);
	}
	return Object.freeze({ kind, id, data } as SessionParticipant);
}

/** `value` as an array of distinct items `admits`, copied once; a RangeError otherwise. */
const inputList = <T,>(
	value: unknown,
	what: string,
	admits: (item: unknown) => item is T,
): readonly T[] => {
	let items: unknown[];
	try {
		if (!Array.isArray(value)) throw new TypeError("not an array");
		items = copyItems(value as readonly unknown[], what);
	} catch {
		throw new RangeError(`${what} must be an array`);
	}
	if (!items.every(admits) || new Set(items).size !== items.length) {
		throw new RangeError(`${what} must hold distinct admitted values`);
	}
	return Object.freeze(items as T[]);
};

/** A close request the port admits, as a frozen copy; a RangeError otherwise. */
export function checkSessionCloseRequest(request: SessionCloseRequest): SessionCloseRequest {
	const what = "session close request";
	const cause = inputField(request, "cause", what);
	if (!isOneOf(SESSION_CLOSE_CAUSES, cause)) {
		throw new RangeError(`${what}: cause must be one of ${SESSION_CLOSE_CAUSES.join(", ")}`);
	}
	const steps = inputList(
		inputField(request, "steps", what),
		`${what}: steps`,
		(step): step is string => typeof step === "string" && STEP_NAME.test(step),
	);
	const perParticipant = inputList(
		inputField(request, "perParticipant", what),
		`${what}: perParticipant`,
		(kind) => isOneOf(SESSION_PARTICIPANT_KINDS, kind),
	);
	const retainMs = inputField(request, "retainMs", what);
	if (
		!Number.isInteger(retainMs) ||
		(retainMs as number) < 0 ||
		(retainMs as number) > MAX_DURATION_MS
	) {
		throw new RangeError(
			`${what}: retainMs must be a whole number of milliseconds from 0 to ${MAX_DURATION_MS}`,
		);
	}
	return Object.freeze({ cause, steps, perParticipant, retainMs: retainMs as number });
}

/** A sid or sub the port admits: 1 to 512 characters, no lone surrogate; a RangeError otherwise. */
export function checkSessionLifecycleKey(value: string, name: string): string {
	if (!isKey(value)) {
		throw new RangeError(
			`session lifecycle: ${name} must be 1 to ${SESSION_LIFECYCLE_MAX_KEY_LENGTH} characters`,
		);
	}
	return value;
}

/** A session's end the port admits: a `Date` with a finite time, copied; a RangeError otherwise. */
export function checkSessionExpiresAt(value: Date): Date {
	const expiresAt = dateOf(value);
	if (expiresAt === undefined)
		throw new RangeError("session lifecycle: expiresAt must be a valid Date");
	return expiresAt;
}

/** A work item the port admits: a step name, or a participant's item; a RangeError otherwise. */
export function checkSessionCloseItem(value: string): string {
	if (!isCloseItem(value)) throw new RangeError("session lifecycle: item is no work item");
	return value;
}

/** A listing's cursor the port admits: `""`, the start, or a key; a RangeError otherwise. */
export function checkSessionListingCursor(value: string): string {
	if (value !== "" && !isKey(value)) {
		throw new RangeError(
			`session lifecycle: after must be "" or 1 to ${SESSION_LIFECYCLE_MAX_KEY_LENGTH} characters of well-formed text`,
		);
	}
	return value;
}

/** A listing's limit the port admits: a whole number from 1 to 1000; a RangeError otherwise. */
export function checkSessionListingLimit(value: number): number {
	if (!Number.isInteger(value) || value < 1 || value > SESSION_LIFECYCLE_MAX_LISTING) {
		throw new RangeError(
			`session lifecycle: limit must be a whole number from 1 to ${SESSION_LIFECYCLE_MAX_LISTING}`,
		);
	}
	return value;
}
