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
 * Steps 1 to 4 of `admitSession`, each failing closed: the claim, the live
 * read, the subject, the renewal nonce, the session's lifecycle and the
 * revocation boundary, then the
 * store's step-up capability over the live record. The session store, the
 * lifecycle store, the boundary and the audit sink are read here and nowhere
 * else in admission,
 * each off `deps` once; an outage, a read of either store off `deps` that
 * throws, or a store that throws when its capability is read, is answered
 * through admission's `unavailable`, which logs it. The sink is read only
 * to audit a subject mismatch, and a read of it that throws fails as that
 * audit: the answer stands.
 */

import { emitAuditEvent } from "../audit/factory.mjs";
import type { AuditSink } from "../audit/types.mjs";
import {
	claimCoveredByRevocationBoundary,
	DEFAULT_SUBJECT_REVOCATION_SKEW_MS,
} from "../jwt/verify.mjs";
import { readVersionedSessionLifecycle } from "../user-sessions/lifecycle/readers.mjs";
import { isRenewalNonce } from "../user-sessions/renewalNonce.mjs";
import {
	supportsSecondFactorUpdate,
	type UserSession,
	type UserSessionStore,
} from "../user-sessions/types.mjs";
import { nonEmptyString } from "./input-values.mjs";
import type { CheckedRequest } from "./request-check.mjs";
import type { Admission, AdmissionInfrastructureStore } from "./requirement.mjs";

const isValidDate = (value: unknown): value is Date =>
	value instanceof Date && !Number.isNaN(value.getTime());

/**
 * What steps 1 to 4 end in: the answer, when one of them gave it; else the
 * live record, or `null` when there is no store or a token carrier has no
 * `sid`, with whether the store it was read from has the step-up capability
 * (`supportsSecondFactorUpdate`, read once, over a live record alone;
 * `false` without one).
 */
export type LiveSession =
	| { readonly answer: Admission }
	| {
			readonly session: UserSession | null;
			readonly storeRecords: boolean;
			/** The record's renewal nonce, read once; `undefined` without a record or one that holds none. */
			readonly renewalNonce: string | undefined;
	  };

/**
 * Whether a record bound to `bound` — its renewal nonce, read once by the
 * caller — is bound to a cookie session other than the one holding
 * `presented`. A record without one (`undefined`, `null`) is bound to none;
 * a value that is not a nonce binds it to no cookie session at all.
 */
export const renewedAway = (bound: unknown, presented: string | undefined): boolean =>
	bound != null && (!isRenewalNonce(bound) || bound !== presented);

/** The one read of a session record admission makes: the store's answer, or its rejection. */
export const readRecord = (
	store: UserSessionStore,
	sid: string,
): Promise<UserSession | null | undefined> => store.get(sid);

/** Reads the session `checked.claim` names, as `admitSession`'s steps 1 to 4. */
export async function readLiveSession(
	checked: CheckedRequest,
	unavailable: (store: string, err: unknown) => Admission,
): Promise<LiveSession> {
	const { claim: presented, now, logger } = checked;
	const label = checked.action.name;

	// Step 1: the claim.
	if (presented.authenticated !== true) return { answer: { outcome: "unauthenticated" } };
	if (presented.carrier === "cookie" && presented.subject === undefined) {
		// A cookie that says authenticated without a user: not a session this
		// provider wrote. Said at warn with the action alone; nothing to audit.
		logger?.warn({ action: label }, "session_admission_no_subject");
		return { answer: { outcome: "not_live", reason: "no_subject" } };
	}

	// Step 2: the live read. The store is read off `deps` once, in the same
	// guarded section as the record: a read that throws is its outage.
	let userSessionStore: UserSessionStore | undefined;
	let record: UserSession | null | undefined;
	try {
		userSessionStore = checked.readUserSessionStore();
		if (userSessionStore !== undefined && presented.sid !== undefined) {
			record = await readRecord(userSessionStore, presented.sid);
		}
	} catch (err) {
		return { answer: unavailable("user_session" satisfies AdmissionInfrastructureStore, err) };
	}
	let session: UserSession | null = null;
	if (userSessionStore !== undefined && presented.sid === undefined) {
		if (presented.carrier !== "token") return { answer: { outcome: "not_live", reason: "no_sid" } };
	} else if (userSessionStore !== undefined) {
		// `== null`: the port answers `null`, and a store of the deployment's own
		// that answers `undefined` for a missing session is still no session.
		if (
			record == null ||
			nonEmptyString(record.sub) === undefined ||
			!isValidDate(record.authTime) ||
			!isValidDate(record.expiresAt) ||
			!(record.expiresAt.getTime() > now.getTime())
		) {
			return { answer: { outcome: "not_live", reason: "gone" } };
		}
		session = record;
	}

	// Step 3: the subject.
	if (session !== null && presented.subject !== undefined && presented.subject !== session.sub) {
		logger?.warn({ action: label }, "session_admission_subject_mismatch");
		// The sink is read off `deps` here alone, as part of the audit: a read
		// that throws fails as a sink that throws does, and the answer stands.
		let auditSink: AuditSink | undefined;
		try {
			auditSink = checked.readAuditSink();
		} catch {
			auditSink = undefined;
		}
		void emitAuditEvent(auditSink, {
			timestamp: now,
			type: "session.admission.subject_mismatch",
			subject: session.sub,
			details: {
				// The claim's sid, whichever carrier made the claim: the record was read by it.
				sid: presented.sid,
				carrier: presented.carrier,
				claimedSubject: presented.subject,
				recordSubject: session.sub,
			},
		});
		return { answer: { outcome: "not_live", reason: "subject_mismatch" } };
	}

	// Step 3b: the renewal nonce. A record bound to a renewed cookie session
	// is live only for the cookie session holding its nonce: an old express
	// id a concurrent request saved back after the renewal holds another or
	// none. A record without one is bound to nothing; other carriers hold no
	// cookie session to compare.
	// Read once: a store's accessor cannot answer one value to the check, and
	// another to the comparison or to the consumer.
	const bound: unknown = session === null ? undefined : session.renewalNonce;
	if (session !== null && presented.carrier === "cookie") {
		// A value that is not a nonce binds the record to no cookie session,
		// whatever the cookie session holds.
		if (renewedAway(bound, presented.renewalNonce)) {
			return { answer: { outcome: "not_live", reason: "renewed" } };
		}
	}

	// Step 3c: the session's lifecycle, after the subject and the renewal
	// nonce. Closing or closed from its closing commit on is not live, and an
	// absent record reads as closed. A user-session store handed without a
	// lifecycle store fails closed. The store is read off `deps` once, in the
	// same guarded section as its answer, which core's reader holds to the
	// port's types; a record of another subject is no answer for this
	// session, refused as malformed.
	if (session !== null && presented.sid !== undefined) {
		try {
			const lifecycleStore = checked.readSessionLifecycleStore();
			if (lifecycleStore === undefined) {
				throw new TypeError("a user-session store is handed without a session lifecycle store");
			}
			const lifecycle = readVersionedSessionLifecycle(await lifecycleStore.read(presented.sid));
			if (lifecycle !== null && lifecycle.value.sub !== session.sub) {
				throw new TypeError("the session lifecycle record names another subject");
			}
			if (lifecycle === null || lifecycle.value.state !== "active") {
				return { answer: { outcome: "not_live", reason: "closing" } };
			}
		} catch (err) {
			return {
				answer: unavailable("session_lifecycle" satisfies AdmissionInfrastructureStore, err),
			};
		}
	}

	// Step 4: the revocation boundary, against a live record; a token's is
	// verifyJwt's, so the two readings do not double up. The boundary is read
	// off `deps` once, in the same guarded section as its answer. Compared in
	// whole seconds by verifyJwt's rule at the default allowance, as the
	// `auth_time` a token from this session carries is compared.
	if (session !== null && presented.carrier !== "token") {
		try {
			const subjectRevocation = checked.readSubjectRevocation();
			const boundary =
				subjectRevocation === undefined ? null : await subjectRevocation.revokedBefore(session.sub);
			if (boundary !== null && !isValidDate(boundary)) {
				throw new TypeError("the sessions boundary is neither a date nor null");
			}
			if (
				claimCoveredByRevocationBoundary(
					Math.floor(session.authTime.getTime() / 1000),
					boundary,
					DEFAULT_SUBJECT_REVOCATION_SKEW_MS,
				)
			) {
				return { answer: { outcome: "revoked" } };
			}
		} catch (err) {
			return {
				answer: unavailable("revocation_boundary" satisfies AdmissionInfrastructureStore, err),
			};
		}
	}

	// The store's step-up capability, read once over the live record: a
	// store that throws on the read is unavailable, as on any other.
	let storeRecords = false;
	if (session !== null) {
		try {
			storeRecords = supportsSecondFactorUpdate(userSessionStore);
		} catch (err) {
			return { answer: unavailable("user_session" satisfies AdmissionInfrastructureStore, err) };
		}
	}

	return { session, storeRecords, renewalNonce: isRenewalNonce(bound) ? bound : undefined };
}
