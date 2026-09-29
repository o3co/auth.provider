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

import { SUBJECT_REVOCATION_MIN_RETENTION_MS } from "../retention.mjs";
import type { SubjectRevocation, SupportsSessionsOnlyRevocation } from "../types.mjs";

interface Watermark {
	readonly sessionsBeforeMs: number;
	/** `null` while no revocation has ever covered this subject's grants. */
	readonly grantsBeforeMs: number | null;
	readonly expiresAtMs: number;
}

/** Every comparison with NaN is false, so a NaN boundary covers nothing while looking like one. */
const instant = (value: Date, name: string): number => {
	const ms = value?.getTime?.();
	if (typeof ms !== "number" || Number.isNaN(ms)) {
		throw new RangeError(`SubjectRevocation: ${name} must be a date`);
	}
	return ms;
};

/**
 * In-process Map-backed {@link SubjectRevocation}, carrying both the
 * sessions and the grants boundary (see ADR
 * 2026-09-17-federation-grants-offline-delegation). Expired watermarks are
 * dropped when read; there is no background sweep.
 *
 * A second write for the same subject keeps the later value of each field,
 * not the newer call's: a credential change computed on a replica whose
 * clock is behind must not move a line back and resurrect what an earlier
 * one killed. The fields take their maxima independently, so a sessions-only
 * stamp cannot drag the grants boundary forward, nor a late full revocation
 * drag the sessions boundary back.
 */
export function createInMemorySubjectRevocation(): SubjectRevocation &
	SupportsSessionsOnlyRevocation {
	const entries = new Map<string, Watermark>();

	/** The record as it stands, or nothing when it has lapsed. */
	const live = (subject: string): Watermark | undefined => {
		const entry = entries.get(subject);
		if (entry === undefined) return undefined;
		if (entry.expiresAtMs <= Date.now()) {
			entries.delete(subject);
			return undefined;
		}
		return entry;
	};

	const write = (
		subject: string,
		sessionsBeforeMs: number,
		grantsBeforeMs: number | null,
		callerExpiresAtMs: number,
	): void => {
		const existing = live(subject);
		const sessions = Math.max(
			existing?.sessionsBeforeMs ?? Number.NEGATIVE_INFINITY,
			sessionsBeforeMs,
		);
		const grants =
			grantsBeforeMs === null
				? (existing?.grantsBeforeMs ?? null)
				: Math.max(existing?.grantsBeforeMs ?? Number.NEGATIVE_INFINITY, grantsBeforeMs);
		// The floor is about grants and is anchored to the boundary, not a
		// fresh clock: it must outlive every grant consented before that
		// instant, which `activate`'s ceiling bounds absolutely. A caller
		// cannot shorten it. So a credential change (`revokeBefore`) costs a
		// year of retention in every deployment, grants or not: deliberately,
		// since otherwise the boundary could lapse under a grant the caller
		// knew nothing about. A sessions-only stamp costs only the caller's
		// expiry. Entries are reclaimed on a read of the same subject, not
		// swept.
		const grantFloor =
			grants === null ? Number.NEGATIVE_INFINITY : grants + SUBJECT_REVOCATION_MIN_RETENTION_MS;
		entries.set(subject, {
			sessionsBeforeMs: sessions,
			grantsBeforeMs: grants,
			expiresAtMs: Math.max(
				existing?.expiresAtMs ?? Number.NEGATIVE_INFINITY,
				callerExpiresAtMs,
				grantFloor,
			),
		});
	};

	return {
		kind: "memory",

		async revokeBefore(subject, before, expiresAt) {
			const beforeMs = instant(before, "before");
			write(subject, beforeMs, beforeMs, instant(expiresAt, "expiresAt"));
		},

		async revokeSessionsBefore(subject, before, expiresAt) {
			write(subject, instant(before, "before"), null, instant(expiresAt, "expiresAt"));
		},

		async revokedBefore(subject) {
			const entry = live(subject);
			// A fresh `Date` every time: one handed out and then mutated by a
			// caller would otherwise edit the record.
			return entry === undefined ? null : new Date(entry.sessionsBeforeMs);
		},

		async grantsRevokedBefore(subject) {
			const entry = live(subject);
			return entry?.grantsBeforeMs == null ? null : new Date(entry.grantsBeforeMs);
		},
	};
}
