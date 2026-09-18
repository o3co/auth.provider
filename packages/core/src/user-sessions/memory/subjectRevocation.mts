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
 * In-process Map-backed {@link SubjectRevocation} (#296), carrying both
 * boundaries of D13 (#593).
 *
 * GC is lazy — expired watermarks are dropped when read — mirroring
 * `createMemoryAccessTokenDenylist`. No background sweep.
 *
 * A second write for the same subject takes the **later** value per field
 * rather than the newer call's. Two credential changes in quick succession
 * must not have the second one, computed on a replica whose clock is behind,
 * move a line backwards and resurrect what the first one killed — and the two
 * fields take their maxima independently, so a sessions-only stamp at a later
 * instant cannot drag the grants boundary forward with it, and a late full
 * revocation at an earlier instant cannot drag the sessions boundary back.
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
		// The floor is about GRANTS, and it is anchored to the boundary rather
		// than to a freshly sampled clock: what it has to outlive is every
		// grant consented before that instant, and the ceiling `activate`
		// enforces bounds those absolutely (D3). A caller cannot shorten it,
		// and a deployment that has never revoked a grant is not made to keep a
		// year of keys because somebody changed a password.
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
