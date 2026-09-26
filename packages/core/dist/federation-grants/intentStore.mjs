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
 * The second port of D16 (#593, slice 6): what acquisition needs to remember
 * between a backend lodging an intent and a browser coming back from the
 * upstream with a code.
 *
 * Three records and one bound live here, and nothing else does:
 *
 * - the **intent** — what a confidential client asserted and where it wants the
 *   browser returned, which has to survive a navigation the client's own
 *   session does not accompany;
 * - the **consent** challenge — read by the deployment's page and answered
 *   once, atomically, so that an accept and a deny in flight cannot both
 *   apply (D8);
 * - the **connect transaction** — the PKCE verifier, the nonce and the
 *   approved snapshot, consumed exactly once by the callback (D7);
 * - the **bound** on live first-time intents per `(client, subject)`, enforced
 *   where a record is admitted rather than counted in a route.
 *
 * What a grant record knows of an intent is a pointer — its handle and when it
 * lapses — and that lives in {@link FederationGrantStore} (D2). Supersession is
 * settled there, by the pointer, and not here: these keys share a tag of their
 * own, no operation spans both ports, and core orders the two writes once
 * (D16).
 *
 * ## One deadline
 *
 * There is exactly one date in an acquisition: the intent's `expiresAt`, set
 * when the intent is lodged, ten minutes out
 * ({@link FEDERATION_GRANT_FLOW_BUDGET_MS}). The consent and the transaction
 * carry it rather than a deadline of their own, because a record that outlived
 * the intent would be one an activation can no longer use: `activate` refuses a
 * handle the grant's pointer no longer calls current, and nothing moves that
 * date — `nameIntent` refuses a `pending` grant, and no other operation
 * extends a pointer.
 *
 * So it is the whole flow's budget, from lodging to activation, and the
 * operator-visible consequence is in the runbook: a user who sits on the
 * consent page until the ninth minute leaves one minute for the upstream leg,
 * and the remedy is to start again — which supersession already covers.
 *
 * ## Two clocks, kept apart
 *
 * Every operation takes the time from its caller, sampled at the operation and
 * not at the start of the request, and that time decides what the caller is
 * told and which transitions are eligible. What an adapter *reclaims* is
 * judged on the adapter's own clock, as a key TTL is. A caller whose clock is
 * ahead is told the wrong thing once, and costs nothing: no operation deletes a
 * record, frees a reservation or overwrites a resident handle because of the
 * time its caller passed. A time that is not a date is refused and not
 * compared — every comparison with NaN is false, so a record would read as
 * lapsed.
 *
 * ## Nothing here heals itself
 *
 * A record an adapter cannot read is refused, in both directions, as the grant
 * store refuses one: these are security state, and a record that cannot be
 * parsed may be a newer release's. A reader that deleted it would make a
 * rollback destroy live flows. That is deliberately unlike
 * `PendingConsentStore`'s Redis adapter, which reclaims a corrupt record as a
 * second compare-and-delete step.
 */
import { federationGrantExpiresAt } from "./lifetime.mjs";
/**
 * The whole flow's budget: lodging → connect → consent → upstream → callback →
 * activation, in milliseconds. D6 gives the handle ten minutes, and because
 * every later record is capped by the intent's deadline (see the module note),
 * that is the budget for all of it.
 */
export const FEDERATION_GRANT_FLOW_BUDGET_MS = 600_000;
/**
 * How many live first-time intents one client may hold for one subject.
 *
 * This is the only admission control in front of `createPending`: every intent
 * that gets in creates a `pending` grant record that lives to its own
 * deadline. A policy that evicted the oldest instead of refusing — as
 * `PENDING_CONSENT_PER_SESSION_LIMIT` does for parked requests, which own no
 * record outside themselves — would therefore let one client mint unbounded
 * records in the *grant* store, the one with the credential key ring and the
 * subject index, while the intent count stayed at sixteen. Refusing caps grant
 * records at sixteen per `(client, subject)` per flow budget.
 *
 * A reauthorization is not counted: it names an intent on a grant that already
 * exists, so admitting it creates no record, and a subject whose grants are all
 * near renewal must not be locked out by a client's abandoned first attempts.
 * Part of the port rather than of one adapter, so both hold it and the contract
 * suite checks it.
 */
export const FEDERATION_GRANT_FIRST_INTENTS_PER_CLIENT_SUBJECT_LIMIT = 16;
/**
 * `consent.at + lifetimeMs`, as an adapter must compute it when it records an
 * approval (D3): from the answer, and never from the callback that follows it.
 *
 * Here rather than in each adapter so that both compute it the same way, and so
 * that no caller can hand a store an expiry of its own.
 */
export function federationGrantConsentExpiry(consentAt, lifetimeMs) {
    return federationGrantExpiresAt(consentAt, lifetimeMs);
}
