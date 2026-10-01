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
 * The MFA enrollment witness as this package writes it (the MFA ADR's D12):
 * `User.mfaEnrolled`, persisted by the Store through core's optional
 * `UserRepository.markMfaEnrolled`.
 *
 * - Create-then-mark: the witness is marked only after the first counting
 *   factor was written, so a crash between them leaves a factor without a
 *   witness, never a witness without a factor.
 * - Reconciliation: a verified counting factor marks a subject whose login's
 *   `User` does not say it is enrolled, so a mark that failed heals at the
 *   next login.
 * - A mark that fails never undoes what it follows: the caller warns once.
 * - Read only through core's `readMfaEnrollmentWitness`.
 */

import {
	type MfaFactor,
	readMfaEnrollmentWitness,
	supportsMfaEnrollmentWitness,
	type UserRepository,
} from "@o3co/auth-provider-core";

/** What marking the witness came to. */
export type MfaWitnessMark =
	| { readonly outcome: "marked" }
	/** The directory has no `markMfaEnrolled`: said once at boot. */
	| { readonly outcome: "unwritable" }
	| { readonly outcome: "unwritten"; readonly cause: unknown };

/** Writes the witness through the composition's directory, when it can. */
export interface MfaEnrollmentWitness {
	/** Whether the directory can write it (core's `supportsMfaEnrollmentWitness`). */
	readonly writable: boolean;
	/** Marks `subject` enrolled; never throws. */
	mark(subject: string): Promise<MfaWitnessMark>;
}

/** The witness over `repository`; one without `markMfaEnrolled`, or none, writes nothing. */
export function createMfaEnrollmentWitness(
	repository: UserRepository | undefined,
): MfaEnrollmentWitness {
	const writer =
		repository !== undefined && supportsMfaEnrollmentWitness(repository) ? repository : undefined;
	return {
		writable: writer !== undefined,
		async mark(subject) {
			if (writer === undefined) return { outcome: "unwritable" };
			try {
				await writer.markMfaEnrolled(subject, true);
				return { outcome: "marked" };
			} catch (cause) {
				return { outcome: "unwritten", cause };
			}
		},
	};
}

/** Whether a verification of `factor` for the login's `user` marks the witness: a counting factor, a `User` not enrolled. */
export const reconciles = (factor: MfaFactor, user: unknown): boolean =>
	factor.counting === true &&
	(typeof user !== "object" ||
		user === null ||
		readMfaEnrollmentWitness(user as Readonly<Record<string, unknown>>) !== "enrolled");

/**
 * A login whose `User` says the subject enrolled — or says something
 * unreadable — while no counting factor is on record: the factor store was
 * lost or the Store answered wrongly. Never a first binding: admission
 * answers it `unavailable`, and its log line carries this as the cause.
 */
export class MfaEnrollmentStateInconsistentError extends Error {
	readonly reason = "mfa_enrollment_state_inconsistent";

	constructor(readonly witness: "enrolled" | "malformed") {
		super(
			witness === "enrolled"
				? "the enrollment witness says the subject enrolled, and no counting factor is on record"
				: "the enrollment witness is neither true, false nor absent",
		);
		this.name = "MfaEnrollmentStateInconsistentError";
	}
}
