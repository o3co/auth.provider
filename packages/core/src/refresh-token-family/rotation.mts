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
import type {
	RefreshTokenFamily,
	RefreshTokenFamilyRotation,
	RefreshTokenFamilyStore,
} from "./types.mjs";

/**
 * Inputs for the RefreshTokenFamilyRotation composition.
 * Per A3 §6.1.
 */
export interface RefreshTokenFamilyRotationDeps {
	readonly refreshTokenFamilyStore: RefreshTokenFamilyStore;
}

/**
 * Reasons this wrapper attaches to its `updateFamily` decisions. They travel
 * back on the result (`RefreshTokenFamilyUpdateResult.reason`) so the outcome
 * is classified by the decision that actually settled the CAS, rather than by
 * a closure variable read afterwards.
 *
 * They are internal to this composition. The store treats them as opaque, and
 * a different rotation implementation is free to use a different vocabulary.
 */
const REASON_REPLAY_REVOKED = "replay-detected-family-revoked";
const REASON_ALREADY_REVOKED = "family-already-revoked";

/**
 * RefreshTokenFamilyRotation composition: builds a fresh
 * RefreshTokenFamily aggregate on `register`, and translates
 * RefreshTokenFamilyStore.updateFamily outcomes into the 4-variant
 * RefreshTokenFamilyRotationOutcome on `rotate`.
 *
 * ## Replay is revoked inside the CAS, not after it (#274)
 *
 * The replay branch used to abort the CAS and report `replayed`, leaving the
 * caller (`packages/oauth/src/grants/refreshToken.mts`) to revoke the family
 * in a SECOND store write. RFC 6819 §5.2.2.3 wants the whole family dead on
 * replay, and two writes cannot deliver that: between "replay detected,
 * aborted" and "family revoked" a parallel request holding the still-active
 * sibling token could complete its rotation and walk away with a fresh access
 * token, which is most of what the family-revoke defence exists to stop.
 *
 * So the replay branch now COMMITS `{ ...current, revoked: true }` and tags
 * the decision `REASON_REPLAY_REVOKED`. The store's compare-and-swap does the
 * rest: the revocation is applied to exactly the state that was inspected, or
 * the CAS loses and re-reads. A sibling rotation is therefore ordered either
 * strictly before the replay was classified (in which case it was a
 * legitimate rotation of the then-active token) or strictly after the family
 * was revoked (in which case it is refused). There is no longer an "in
 * between" for it to land in.
 *
 * This is also why the return contract needed a third state: a committed
 * replay-revocation and a committed ordinary rotation are the same
 * `{ outcome: "committed" }`, and a closure variable cannot tell them apart
 * given the adapter is free to invoke the updater more than once per call.
 *
 * The already-revoked branch still ABORTS — there is nothing to write, and
 * re-committing an unchanged aggregate would amplify writes on the one path
 * an attacker can drive at will.
 *
 * Defence-in-depth on the aborted branch: any abort whose reason is not
 * `REASON_ALREADY_REVOKED` classifies as `replayed`. If a future code path
 * adds an abort case and forgets its reason, the safest classification is a
 * reject-class outcome (the caller rejects either way, and `replayed` also
 * drives the family-revoke fallback).
 *
 * Per A3 §6.1 + #274.
 */
export function createRefreshTokenFamilyRotation(
	deps: RefreshTokenFamilyRotationDeps,
): RefreshTokenFamilyRotation {
	return {
		async register(newJti, familyId, expiresAtMs) {
			const family: RefreshTokenFamily = Object.freeze({
				familyId,
				activeJti: newJti,
				revoked: false,
				expiresAtMs,
			});
			await deps.refreshTokenFamilyStore.registerFamily(family);
		},

		async rotate(previousJti, newJti, familyId, expiresAtMs) {
			const result = await deps.refreshTokenFamilyStore.updateFamily(familyId, (current) => {
				if (current.revoked) {
					// Nothing to write — the end state this branch wants is
					// already durable.
					return { action: "abort", reason: REASON_ALREADY_REVOKED };
				}
				if (current.activeJti !== previousJti) {
					// #274: the replay IS the revocation. Committing here is what
					// makes detection and family revocation one indivisible write.
					// `activeJti` is deliberately left alone: a revoked family
					// retains the jti that was active when it died (A3 §5.1), and
					// installing the replayed jti would hand the attacker a record
					// that says their token was the live one.
					return {
						action: "commit",
						family: Object.freeze({ ...current, revoked: true }),
						reason: REASON_REPLAY_REVOKED,
					};
				}
				// IH-13: absolute expiry cap. The family TTL is SET ONCE at
				// creation. Subsequent rotations MUST NOT extend the ceiling
				// — `Math.min` clamps a sliding-window-style request back to
				// the original creation value (or honours a smaller caller-
				// supplied value, e.g. a session-bound RT). Per OAuth 2.1
				// BCP §4.14.1.
				//
				// Naming note: `cappedExpiresAtMs` here is the PRE-commit
				// computed value used by the updater. The "rotated" outcome
				// below exposes a same-named field that reads the POST-commit
				// `result.family.expiresAtMs` — for the Redis adapter this
				// drifts forward by a few ms vs the closure value (see
				// `RefreshTokenFamilyRotationOutcome` JSDoc + the Redis
				// `updateFamily` post-EXEC reconstruction comment). They are
				// the same value modulo single-digit-ms drift; consumers
				// must read the field on the outcome, not assume the
				// updater's pre-commit value.
				const cappedExpiresAtMs = Math.min(expiresAtMs, current.expiresAtMs);
				return {
					action: "commit",
					family: Object.freeze({
						...current,
						activeJti: newJti,
						expiresAtMs: cappedExpiresAtMs,
					}),
				};
			});

			switch (result.outcome) {
				case "not-found":
					return Object.freeze({ outcome: "unknown_family" } as const);
				case "aborted":
					// Only the already-revoked branch aborts. Anything else that
					// somehow aborts is classified fail-closed as a replay.
					return result.reason === REASON_ALREADY_REVOKED
						? Object.freeze({ outcome: "revoked" } as const)
						: Object.freeze({ outcome: "replayed", familyRevoked: false } as const);
				case "committed":
					if (result.reason === REASON_REPLAY_REVOKED) {
						// #274: the family was revoked by this very commit, so the
						// caller MUST NOT issue a second revoke. `familyRevoked`
						// says so explicitly rather than making the caller infer it
						// from the outcome name.
						return Object.freeze({ outcome: "replayed", familyRevoked: true } as const);
					}
					// IH-13: surface the committed ceiling so the grant handler
					// can detect when the cap reduced the requested expiry and
					// (Phase F) re-mint the issued JWT to match. For v0.5.1
					// the storage cap alone is the security primary; JWT exp
					// alignment is deferred per the spec's open question.
					return Object.freeze({
						outcome: "rotated",
						cappedExpiresAtMs: result.family.expiresAtMs,
					} as const);
			}
		},
	};
}
