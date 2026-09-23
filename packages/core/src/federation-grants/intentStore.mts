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
 * What a backend lodged, and what every later step is judged against (D6).
 *
 * Immutable: the callback must decide against what the client asserted and the
 * user was shown, not against configuration as it stands minutes later. The
 * connection's revisions are pinned here for that reason, and the callback
 * refuses when they have moved.
 *
 * Every field is a required key (#626): `resource` and `upstreamSubject` hold
 * `undefined` where there is none. Both stores copy the intent field by
 * field, and a copy that lost either widened the flow — the upstream asked
 * without the audience the connection narrows it to, or the callback linking
 * whichever upstream account signed in instead of the one the client said to
 * expect. Naming the key makes that copy a compile error.
 */
export interface FederationGrantIntent {
	/** Opaque, single-use, 256 bits. Addresses this record and nothing else. */
	readonly handle: string;
	/**
	 * `"initial"` lodges a new grant and counts against the bound;
	 * `"reauthorization"` names an intent on a grant that exists (D6).
	 */
	readonly kind: "initial" | "reauthorization";
	/** The grant this intent will activate: a fresh ID, or the existing one being renewed. */
	readonly grantId: string;
	/** The confidential client that lodged it, as authenticated. */
	readonly clientId: string;
	/** The local subject it was lodged for. An assertion until a session proves it (D7). */
	readonly subject: string;

	readonly connection: string;
	/** The federation the connection names, resolved at lodging. */
	readonly federation: string;
	/** Pinned at lodging (D4): the callback refuses when either has moved. */
	readonly identityRevision: string;
	readonly authorizationRevision: string;
	/** The connection's `callbackURL`, exactly as configured: authorization and exchange use this spelling. */
	readonly callbackUri: string;
	/** Validated against the connection's ceiling at lodging (D6); what consent shows and the upstream is asked for. */
	readonly scopes: readonly string[];
	/** RFC 8707, from the connection; `undefined` when it names none. */
	readonly resource: string | undefined;
	/** The connection's extra authorization parameters. Never a client's. */
	readonly authorizationParams: Readonly<Record<string, string>>;

	/** Where the browser is sent at the end: one of the client's `federationGrantRedirectUris`. */
	readonly redirectUri: string;
	/** The client's own state, echoed on every exit. Never the upstream's. */
	readonly clientState: string;
	/**
	 * What the client already expects the upstream account to be, checked at the
	 * callback (D6); `undefined` when the client named none.
	 */
	readonly upstreamSubject: string | undefined;
	/** The grant lifetime that applied, in milliseconds: clamped at lodging, shown at consent. */
	readonly lifetimeMs: number;
	readonly createdAt: Date;
	/** The one deadline. Consent and transaction carry it; nothing extends it. */
	readonly expiresAt: Date;
	/** Correlates the audit of every step of one flow. Not an authorization input. */
	readonly correlationId: string;
}

/**
 * The browser a flow started in, as both halves of this provider's session
 * identity (D7).
 *
 * `sessionId` is the express-session record the challenge was issued to, and
 * what makes a challenge answerable from that browser alone. `sid` is the
 * durable {@link UserSession}, re-read at every step so that a session revoked
 * in between cannot finish a flow, and what `grant.consent.sid` records.
 */
export interface FederationGrantBrowserBinding {
	readonly sessionId: string;
	readonly sid: string;
	readonly subject: string;
}

/** A consent challenge parked for the deployment's page to answer (D8). */
export interface FederationGrantConsentRecord {
	/** 32 random bytes, reaching the page through the redirect and nowhere else. */
	readonly challenge: string;
	readonly intentHandle: string;
	readonly binding: FederationGrantBrowserBinding;
	/** What the page shows, and what an answer consents to: the intent's scopes. */
	readonly scopes: readonly string[];
	/** What the page shows as the duration; the grant's expiry is dated from the answer, not from here. */
	readonly lifetimeMs: number;
	readonly createdAt: Date;
	/** The intent's deadline. Parking never extends it. */
	readonly expiresAt: Date;
}

/**
 * What an approval created and the callback consumes exactly once (D7).
 *
 * It carries the intent as a snapshot because the intent is spent by the answer
 * that created this: the callback decides against what was approved, and a
 * second look at a record the answer removed would find nothing.
 */
export interface FederationGrantConnectTransaction {
	/** The upstream `state`. Never the client's own. */
	readonly state: string;
	readonly intent: FederationGrantIntent;
	readonly binding: FederationGrantBrowserBinding;
	readonly codeVerifier: string;
	readonly nonce: string;
	/** What the user agreed to, and when: `grant.consent` is written from this (D8). */
	readonly consent: {
		readonly at: Date;
		readonly sid: string;
		readonly scopes: readonly string[];
	};
	/** `consent.at + lifetimeMs`, computed by the store at the answer so no later step can move it (D3). */
	readonly grantExpiresAt: Date;
	readonly createdAt: Date;
	/** The intent's deadline. An approval does not restart it. */
	readonly expiresAt: Date;
}

/** How the page answered, with what an approval needs to continue upstream. */
export type FederationGrantConsentAnswer =
	| { readonly decision: "deny" }
	| {
			readonly decision: "accept";
			/** The upstream state this flow will use, fresh and unguessable. */
			readonly state: string;
			readonly codeVerifier: string;
			readonly nonce: string;
	  };

/**
 * What an answer did.
 *
 * - `empty` — there was nothing to answer: an unknown, expired or already
 *   answered challenge, a challenge another browser holds, or an intent that is
 *   no longer live. One outcome for all of them, on purpose: the route answers
 *   them identically, so that whether a challenge belongs to somebody else is
 *   not something a caller can find out.
 * - `denied` / `accepted` — the answer applied, and nothing else can now apply.
 * - `refused` — the answer could have applied but the store would not: the
 *   `state` an approval brought is already a resident transaction's, so
 *   accepting would either overwrite that flow or hand two flows one record.
 *   Nothing is spent. It is its own outcome rather than `empty` because it is a
 *   fault on this side: the operator should see it, and the user should not be
 *   told to start again as if their link had expired.
 */
export type FederationGrantConsentAnswerResult =
	| { readonly outcome: "empty" }
	| { readonly outcome: "denied"; readonly intent: FederationGrantIntent }
	| { readonly outcome: "accepted"; readonly transaction: FederationGrantConnectTransaction }
	| { readonly outcome: "refused"; readonly reason: "state_collision" };

/**
 * Why an intent was not admitted.
 *
 * - `limit` — the `(client, subject)` bound is full.
 * - `collision` — a *different* record is resident under this handle. Refused
 *   even when that record is invisible to this caller's clock: a handle is
 *   taken for as long as a record is there under it, not for as long as a
 *   caller can see it.
 * - `expired` — the record's own deadline is not after the caller's `now`;
 *   there is nothing to store.
 * - `closed` — this handle was answered or finished. The marker outlives the
 *   record so that a retried write cannot resurrect a spent intent.
 */
export type FederationGrantIntentRefusal = "limit" | "collision" | "expired" | "closed";

export type FederationGrantIntentWrite =
	| { readonly outcome: "created" | "unchanged" }
	| { readonly outcome: "refused"; readonly reason: FederationGrantIntentRefusal };

export interface FederationGrantIntentStore {
	/** Non-empty; names the adapter in logs and diagnostics. */
	readonly kind: string;

	/**
	 * Admits an intent: reserves the bound's capacity and writes the record, as
	 * one step.
	 *
	 * Atomic on purpose. Counting and then inserting lets concurrent clients
	 * exceed the bound; inserting and then counting leaves uncounted records
	 * behind a crash.
	 *
	 * Writing the *same* record again is `unchanged`: it neither extends the
	 * deadline nor takes a second place against the bound, so core may retry a
	 * write whose answer it lost. Any other record under a resident handle is a
	 * `collision`, and no write ever replaces one.
	 */
	putIntent(record: FederationGrantIntent, now: Date): Promise<FederationGrantIntentWrite>;

	/**
	 * The intent, if it is live: admitted, not answered, not finished, and not
	 * past its deadline on the caller's clock. A copy — what the caller does with
	 * it is not what the next caller reads.
	 */
	getIntent(handle: string, now: Date): Promise<FederationGrantIntent | null>;

	/**
	 * Parks a consent challenge for a live intent, bound to the browser that
	 * asked, and answers with the record the page will read.
	 *
	 * One challenge per intent: a second start from the same browser is given
	 * the one already parked, with its deadline untouched, so that a user who
	 * reloads the connect link does not mint challenges. A start from any other
	 * browser gets `null`, as does one for an intent that is not live — the
	 * route cannot tell those apart, and must not.
	 */
	parkConsent(input: {
		readonly handle: string;
		readonly challenge: string;
		readonly binding: FederationGrantBrowserBinding;
		readonly now: Date;
	}): Promise<FederationGrantConsentRecord | null>;

	/**
	 * The parked record, for the page's read. Does not spend it: the page shows
	 * what is being asked before anybody answers, and a reload must not consume
	 * the question. The binding is returned rather than checked — the route
	 * compares it, and answers one way for every record it may not have.
	 */
	getConsent(challenge: string, now: Date): Promise<FederationGrantConsentRecord | null>;

	/**
	 * Answers a challenge, once, as one step: the challenge is removed, the
	 * intent is spent, and an approval creates the transaction — or none of it
	 * happens.
	 *
	 * Reading the challenge and then removing it would let an accept and a deny
	 * in flight both apply; spending the intent and then creating the
	 * transaction would let a crash consume a valid consent with nothing to
	 * continue with.
	 *
	 * A denial releases the capacity it reserved. An approval keeps it until
	 * {@link finishIntent}: the flow is still running, and the record the
	 * callback will activate is still to be written.
	 */
	answerConsent(input: {
		readonly challenge: string;
		readonly binding: FederationGrantBrowserBinding;
		readonly answer: FederationGrantConsentAnswer;
		readonly now: Date;
	}): Promise<FederationGrantConsentAnswerResult>;

	/**
	 * Reads and removes the transaction the callback presents, as one step, and
	 * only when it belongs to the connection the callback arrived on.
	 *
	 * Reading and then removing would let two callbacks exchange one code. A
	 * transaction of another connection is left exactly where it is: a callback
	 * on the wrong path must not spend somebody else's flow.
	 */
	consumeTransaction(input: {
		readonly state: string;
		readonly connection: string;
		readonly now: Date;
	}): Promise<FederationGrantConnectTransaction | null>;

	/**
	 * Ends a flow: closes the handle, drops whatever consent or transaction is
	 * left under it, and releases its capacity — once, however many times this
	 * is called.
	 *
	 * Called after every terminal outcome, including the failures. It never
	 * touches a grant: what a grant knows of this intent is its pointer, and
	 * ending that is `retireIntent`'s (D13).
	 */
	finishIntent(handle: string, now: Date): Promise<void>;
}

/**
 * `consent.at + lifetimeMs`, as an adapter must compute it when it records an
 * approval (D3): from the answer, and never from the callback that follows it.
 *
 * Here rather than in each adapter so that both compute it the same way, and so
 * that no caller can hand a store an expiry of its own.
 */
export function federationGrantConsentExpiry(consentAt: Date, lifetimeMs: number): Date {
	return federationGrantExpiresAt(consentAt, lifetimeMs);
}

// ---------------------------------------------------------------------------
// ComponentMap slot
// ---------------------------------------------------------------------------
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		/**
		 * Acquisition's records (#593, D16). Optional: a deployment that spends
		 * grants without issuing them needs none, and one with federation grants
		 * enabled is refused at boot without it.
		 */
		readonly federationGrantIntentStore?: FederationGrantIntentStore;
	}
}
