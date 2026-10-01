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

import {
	checkSecondFactorEvent,
	copySessionAuthentication,
	expectsRenewalNonce,
	recordableSessionAuthentication,
	sessionAfterSecondFactor,
} from "../authentication.mjs";
import { recordableEnrollmentFacts } from "../enrollmentFacts.mjs";
import type {
	CreateUserSessionInput,
	SessionAuthentication,
	SessionEnrollmentFacts,
	SupportsSecondFactorUpdate,
	UserSession,
	UserSessionClaims,
	UserSessionStore,
} from "../types.mjs";

interface Stored {
	sid: string;
	sub: string;
	authTime: Date;
	createdAt: Date;
	expiresAt: Date;
	claims: Record<string, unknown>;
	/** A required key, as on the session: the copy into a record names it. */
	amr: readonly string[] | undefined;
	/** The MFA ADR's D9; a required key, as on the session. Kept as a copy that shares nothing. */
	authentication: SessionAuthentication | undefined;
	/** What `recordableEnrollmentFacts` answered at `create`; `undefined` for none. */
	enrollmentFacts: SessionEnrollmentFacts | undefined;
	/** The renewal nonce the last escalation carried; `undefined` for none. */
	renewalNonce: string | undefined;
}

/**
 * Defensive deep-copy of claims. `groups` is the only known array-valued
 * standard claim — extend when new array-valued claims are added to
 * UserSessionClaims.
 */
const cloneClaims = (c: UserSessionClaims | Record<string, unknown>): Record<string, unknown> => {
	const out: Record<string, unknown> = { ...c };
	const groups = (c as { groups?: unknown }).groups;
	if (Array.isArray(groups)) {
		out.groups = [...groups];
	}
	return out;
};

/** The session a record holds, as a copy that shares nothing with it. */
const toSession = (s: Stored): UserSession => ({
	sid: s.sid,
	sub: s.sub,
	authTime: new Date(s.authTime.getTime()),
	createdAt: new Date(s.createdAt.getTime()),
	expiresAt: new Date(s.expiresAt.getTime()),
	claims: cloneClaims(s.claims) as UserSessionClaims,
	amr: s.amr ? [...s.amr] : undefined,
	authentication: s.authentication ? copySessionAuthentication(s.authentication) : undefined,
	// Optional on the session: left out when none was recorded.
	...(s.enrollmentFacts === undefined ? {} : { enrollmentFacts: { ...s.enrollmentFacts } }),
	...(s.renewalNonce === undefined ? {} : { renewalNonce: s.renewalNonce }),
});

/**
 * In-memory UserSessionStore, with the step-up capability (the MFA ADR's D9).
 * Single-process only. Atomicity comes from Node's single event loop —
 * `Map.get/set/delete` are synchronous, and `recordSecondFactor` reads,
 * computes and writes with no `await` between, so two recorded at once apply
 * one after the other.
 */
export function createInMemoryUserSessionStore(): UserSessionStore & SupportsSecondFactorUpdate {
	const sessions = new Map<string, Stored>();

	const readLive = (sid: string): Stored | null => {
		const s = sessions.get(sid);
		if (!s) return null;
		if (s.expiresAt.getTime() <= Date.now()) {
			sessions.delete(sid);
			return null;
		}
		return s;
	};

	return {
		kind: "memory",
		async create(input: CreateUserSessionInput) {
			// An Invalid Date's time is NaN, which is never `<= now`: such a
			// session would be live for ever. Refused as the Redis store refuses it.
			if (!Number.isFinite(input.expiresAt.getTime())) {
				throw new RangeError(`UserSession ${input.sid}: expiresAt must be a valid date`);
			}
			// A login time, handed back as the id_token's `auth_time`: an Invalid
			// Date is none, and one before the epoch is none the Redis store can
			// read back. Refused as there.
			const authTimeMs = input.authTime.getTime();
			if (!Number.isFinite(authTimeMs) || authTimeMs < 0) {
				throw new RangeError(
					`UserSession ${input.sid}: authTime must be a valid date at or after the epoch`,
				);
			}
			// How the session was established: what core's
			// `recordableSessionAuthentication` answers — only what
			// `SessionAuthentication` admits, its `mfaAt` no later than this
			// store's clock — recorded as answered, never `input.authentication`.
			// The Redis store records the same, so the two refuse the same values.
			const authentication = recordableSessionAuthentication(
				input.sid,
				input.authentication,
				Date.now(),
			);
			// Likewise the enrollment facts: a copy of what the type admits.
			const enrollmentFacts = recordableEnrollmentFacts(input.sid, input.enrollmentFacts);
			if (input.expiresAt.getTime() <= Date.now()) {
				throw new Error(`UserSession ${input.sid}: expiresAt is in the past`);
			}
			// GC expired entry first so duplicate-check semantics match `get()`.
			if (readLive(input.sid) !== null) {
				throw new Error(`UserSession ${input.sid} already exists`);
			}
			sessions.set(input.sid, {
				sid: input.sid,
				sub: input.sub,
				authTime: new Date(input.authTime.getTime()),
				createdAt: new Date(),
				expiresAt: new Date(input.expiresAt.getTime()),
				claims: cloneClaims(input.claims),
				amr: input.amr ? [...input.amr] : undefined,
				// Already a copy, its `mfaAt` no later than this store's clock.
				authentication,
				enrollmentFacts,
				renewalNonce: undefined,
			});
		},
		async get(sid: string): Promise<UserSession | null> {
			const s = readLive(sid);
			if (!s) return null;
			return toSession(s);
		},
		async recordSecondFactor(sid, event) {
			// A bad event is refused before anything is read, gone session or not,
			// its time judged on this store's clock.
			const nowMs = Date.now();
			checkSecondFactorEvent(event, nowMs);
			const s = readLive(sid);
			if (!s) return null;
			// A completion another one overtook: the session moved to its nonce.
			if (!expectsRenewalNonce(s.renewalNonce, event)) return null;
			const next = sessionAfterSecondFactor(toSession(s), event, nowMs);
			if (next === null) return null;
			// A field write: `expiresAt`, and everything else, stay as they were.
			s.amr = [...next.amr];
			s.authentication = copySessionAuthentication(next.authentication);
			if (event.renewalNonce !== undefined) s.renewalNonce = event.renewalNonce;
			return toSession(s);
		},
		async delete(sid: string) {
			sessions.delete(sid);
		},
	};
}
