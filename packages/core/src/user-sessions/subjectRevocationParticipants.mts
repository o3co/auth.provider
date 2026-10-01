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
 * Subject-revocation participants: what a feature contributes
 * (`subjectRevocationParticipants`, by name) to clear its own state for a
 * subject whose credentials were revoked, and the one pass that runs them.
 *
 * Guarantees of the pass ({@link runSubjectRevocationParticipants}):
 *
 * - It runs only after a revocation that completed. While an old credential
 *   may still stand, nothing a participant would give back (attempts, a
 *   lock) is given back: every participant is held back and named.
 * - Participants run in the order listed, each awaited before the next.
 * - It never throws. A participant's throw or rejection is reported under its
 *   name and the next one still runs; a listing that throws is an outcome
 *   field; a logger that throws costs its line, never the pass.
 * - A failure carries the error's name and an own reason code alone: another
 *   module's internals stay out of the caller's report, and a name or code
 *   that is, or holds, the subject is dropped.
 */

import type { Logger } from "../logging/Logger.mjs";
import {
	guardedRead,
	isError,
	isLoggableReason,
	loggableError,
} from "../logging/loggableError.mjs";

/**
 * Clears one feature's state for a subject. Called again on a retry of the
 * revocation, so it must be idempotent; a rejection is reported, not retried.
 */
export interface SubjectRevocationParticipant {
	run(input: { readonly subject: string }): Promise<void>;
}

/** Whether `value` is a {@link SubjectRevocationParticipant}: a non-array object whose `run` is a function. */
export function isSubjectRevocationParticipant(
	value: unknown,
): value is SubjectRevocationParticipant {
	return (
		typeof value === "object" &&
		value !== null &&
		!Array.isArray(value) &&
		typeof (value as { run?: unknown }).run === "function"
	);
}

/**
 * The read side of the `subjectRevocationParticipants` kind — the synthetic
 * key `subjectRevocationParticipantResolver`: every participant by name,
 * `entries()` in registration order.
 */
export interface SubjectRevocationParticipantResolver {
	readonly get: (name: string) => SubjectRevocationParticipant | undefined;
	readonly entries: () => IterableIterator<readonly [string, SubjectRevocationParticipant]>;
}

/**
 * A participant's name: lower-case words of letters and digits joined by `.`
 * or `-`, at most 64 characters, so it is safe in a report and a log line.
 */
const PARTICIPANT_NAME = /^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$/;
const PARTICIPANT_NAME_MAX_LENGTH = 64;

export const isSubjectRevocationParticipantName = (name: string): boolean =>
	name.length <= PARTICIPANT_NAME_MAX_LENGTH && PARTICIPANT_NAME.test(name);

/** An error's `name` that is an identifier (`TypeError`, `RedisError`); anything else reads as `Error`. */
const ERROR_NAME = /^[A-Za-z][A-Za-z0-9]{0,63}$/;

/**
 * What a report keeps of a participant's error: its name and a reason code,
 * never its text — another module's internals stay out of the caller's report.
 */
export interface SubjectRevocationParticipantError {
	/**
	 * The error's `name` when it is an identifier that neither is nor holds the
	 * subject, `"Error"` otherwise; `"NonError"` for a thrown value that is not
	 * an Error, or that cannot be inspected.
	 */
	readonly name: string;
	/** An own `reason` that is a code (`isLoggableReason`) and neither is nor holds the subject. */
	readonly reason?: string;
}

export interface SubjectRevocationParticipantFailure {
	/** The name the participant was contributed under. */
	readonly name: string;
	readonly error: SubjectRevocationParticipantError;
}

/** An own `reason`, read so that asking cannot throw; `undefined` when there is none or it threw. */
function ownReason(thrown: object): unknown {
	try {
		return Object.hasOwn(thrown, "reason") ? guardedRead(thrown, "reason")?.value : undefined;
	} catch {
		return undefined;
	}
}

/** Never throws: a value whose inspection throws reads as `NonError`. */
function participantError(thrown: unknown, subject: string): SubjectRevocationParticipantError {
	if (!isError(thrown)) return { name: "NonError" };
	const mentionsSubject = (text: string): boolean => subject.length > 0 && text.includes(subject);
	const name = guardedRead(thrown, "name")?.value;
	const reason = ownReason(thrown);
	const projected =
		typeof name === "string" && ERROR_NAME.test(name) && !mentionsSubject(name) ? name : "Error";
	return isLoggableReason(reason) && !mentionsSubject(reason)
		? { name: projected, reason }
		: { name: projected };
}

/** A logger's failure costs its line, never the pass. */
function logged(write: () => void): void {
	try {
		write();
	} catch {
		// The pass's outcome is the report; a line it could not write changes nothing in it.
	}
}

export interface SubjectRevocationParticipantsOutcome {
	/** Names held back because the revocation was incomplete; none were called. */
	readonly participantsHeldBack: readonly string[];
	readonly participantFailures: readonly SubjectRevocationParticipantFailure[];
	/** Present when the participants could not be listed: none was called. */
	readonly listingError?: { readonly error: unknown };
}

/**
 * Runs `participants` for `subject`, or holds them back when the revocation
 * did not complete. The participants are listed once, before the first runs.
 * Never throws.
 */
export async function runSubjectRevocationParticipants(opts: {
	readonly subject: string;
	readonly participants: SubjectRevocationParticipantResolver;
	readonly revocationComplete: boolean;
	readonly logger?: Logger;
}): Promise<SubjectRevocationParticipantsOutcome> {
	const { subject, logger } = opts;
	let listed: ReadonlyArray<readonly [string, SubjectRevocationParticipant]>;
	try {
		// Each entry taken apart here, so an entry that is not a pair is a
		// listing error, not a throw in the middle of the pass.
		listed = [...opts.participants.entries()].map(
			([name, participant]) => [name, participant] as const,
		);
	} catch (error) {
		logged(() =>
			logger?.error({ err: loggableError(error), subject }, "revoke_all_list_participants_failed"),
		);
		return { participantsHeldBack: [], participantFailures: [], listingError: { error } };
	}
	if (!opts.revocationComplete) {
		const participantsHeldBack = listed.map(([name]) => name);
		if (participantsHeldBack.length > 0) {
			logged(() =>
				logger?.warn(
					{ subject, participants: participantsHeldBack },
					"revoke_all_participants_held_back",
				),
			);
		}
		return { participantsHeldBack, participantFailures: [] };
	}
	const participantFailures: SubjectRevocationParticipantFailure[] = [];
	for (const [name, participant] of listed) {
		try {
			await participant.run({ subject });
		} catch (error) {
			participantFailures.push({ name, error: participantError(error, subject) });
			logged(() =>
				logger?.error(
					{ err: loggableError(error), subject, participant: name },
					"revoke_all_participant_failed",
				),
			);
		}
	}
	return { participantsHeldBack: [], participantFailures };
}
