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
 * The federation-grant intent store port: what acquisition remembers between a
 * backend lodging an intent and a browser returning from the upstream with a
 * code. It holds:
 *
 * - the intent: what a confidential client asserted and where the browser
 *   returns, surviving a navigation the client's session does not accompany;
 * - the consent challenge, answered once atomically so an accept and a deny in
 *   flight cannot both apply;
 * - the connect transaction (PKCE verifier, nonce, approved snapshot),
 *   consumed exactly once by the callback;
 * - the bound on live first-time intents per `(client, subject)`, enforced
 *   where a record is admitted.
 *
 * A grant knows an intent only by a pointer in {@link FederationGrantStore},
 * where supersession is settled; no operation spans both ports.
 *
 * One deadline: the intent's `expiresAt` ({@link FEDERATION_GRANT_FLOW_BUDGET_MS}
 * after lodging) caps the consent and the transaction too, since `activate`
 * refuses a handle the grant's pointer no longer calls current, and nothing
 * extends it.
 *
 * Two clocks: the caller's `now` decides what it is told; what an adapter
 * reclaims is judged on its own clock, like a key TTL. No operation deletes,
 * frees or overwrites anything because of a caller's time, and a time that is
 * not a date is refused (every comparison with NaN is false).
 *
 * Nothing heals itself: an unreadable record is refused, never deleted, since
 * it may be a newer release's and deleting it would make a rollback destroy
 * live flows (unlike `PendingConsentStore`'s Redis adapter). See the storage
 * decision of ADR 2026-09-17 (federation grants).
 */

import { federationGrantExpiresAt } from "./lifetime.mjs";

/**
 * The whole flow's budget, lodging to activation, in milliseconds. Every later
 * record is capped by the intent's deadline, so this bounds all of it.
 */
export const FEDERATION_GRANT_FLOW_BUDGET_MS = 600_000;

/**
 * How many live first-time intents one client may hold for one subject: the
 * only admission control in front of `createPending`. It refuses rather than
 * evicting, because every admitted intent creates a `pending` grant record that
 * lives to its own deadline; eviction would let one client mint unbounded
 * records in the grant store. A reauthorization is not counted: it creates no
 * record, and abandoned first attempts must not lock out renewals. Part of the
 * port, so both adapters hold it and the contract suite checks it.
 */
export const FEDERATION_GRANT_FIRST_INTENTS_PER_CLIENT_SUBJECT_LIMIT = 16;

/**
 * What a backend lodged, and what every later step is judged against.
 * Immutable: the callback decides against what the client asserted and the
 * user was shown, not against configuration minutes later, so the connection's
 * revisions are pinned and the callback refuses when they have moved.
 *
 * Every field is a required key (`resource` and `upstreamSubject` hold
 * `undefined` where there is none), so a store copying the intent field by
 * field cannot silently drop one and widen the flow.
 */
export interface FederationGrantIntent {
	/** Opaque, single-use, 256 bits. Addresses this record and nothing else. */
	readonly handle: string;
	/**
	 * `"initial"` lodges a new grant and counts against the bound;
	 * `"reauthorization"` names an intent on a grant that exists.
	 */
	readonly kind: "initial" | "reauthorization";
	/** The grant this intent will activate: a fresh ID, or the existing one being renewed. */
	readonly grantId: string;
	/** The confidential client that lodged it, as authenticated. */
	readonly clientId: string;
	/** The local subject it was lodged for. An assertion until a session proves it. */
	readonly subject: string;

	readonly connection: string;
	/** The federation the connection names, resolved at lodging. */
	readonly federation: string;
	/** Pinned at lodging: the callback refuses when either has moved. */
	readonly identityRevision: string;
	readonly authorizationRevision: string;
	/** The connection's `callbackURL`, exactly as configured: authorization and exchange use this spelling. */
	readonly callbackUri: string;
	/** Validated against the connection's ceiling at lodging; what consent shows and the upstream is asked for. */
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
	 * callback; `undefined` when the client named none.
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
 * identity. `sessionId` is the express-session record the challenge was issued
 * to, so only that browser can answer it. `sid` is the durable
 * {@link UserSession}, re-read at every step so a session revoked in between
 * cannot finish a flow, and what `grant.consent.sid` records.
 */
export interface FederationGrantBrowserBinding {
	readonly sessionId: string;
	readonly sid: string;
	readonly subject: string;
}

/** A consent challenge parked for the deployment's page to answer. */
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
 * What an approval created and the callback consumes exactly once. It carries
 * the intent as a snapshot because the answer that created it spent the intent:
 * the callback decides against what was approved.
 */
export interface FederationGrantConnectTransaction {
	/** The upstream `state`. Never the client's own. */
	readonly state: string;
	readonly intent: FederationGrantIntent;
	readonly binding: FederationGrantBrowserBinding;
	readonly codeVerifier: string;
	readonly nonce: string;
	/** What the user agreed to, and when: `grant.consent` is written from this. */
	readonly consent: {
		readonly at: Date;
		readonly sid: string;
		readonly scopes: readonly string[];
	};
	/** `consent.at + lifetimeMs`, computed by the store at the answer so no later step can move it. */
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
 * - `empty`: nothing to answer (an unknown, expired or answered challenge, one
 *   another browser holds, or an intent no longer live). One outcome on
 *   purpose, so a caller cannot learn whether a challenge is someone else's.
 * - `denied` / `accepted`: the answer applied, and nothing else can now apply.
 * - `refused`: the approval's `state` is already a resident transaction's, so
 *   accepting would overwrite that flow or share one record. Nothing is spent.
 *   Distinct from `empty` because it is a fault on this side: the operator
 *   should see it, and the user should not be told their link expired.
 */
export type FederationGrantConsentAnswerResult =
	| { readonly outcome: "empty" }
	| { readonly outcome: "denied"; readonly intent: FederationGrantIntent }
	| { readonly outcome: "accepted"; readonly transaction: FederationGrantConnectTransaction }
	| { readonly outcome: "refused"; readonly reason: "state_collision" };

/**
 * Why an intent was not admitted.
 *
 * - `limit`: the `(client, subject)` bound is full.
 * - `collision`: a different record is resident under this handle, even one
 *   this caller's clock cannot see.
 * - `expired`: the record's own deadline is not after the caller's `now`.
 * - `closed`: this handle was answered or finished; the marker outlives the
 *   record so a retried write cannot resurrect a spent intent.
 */
export type FederationGrantIntentRefusal = "limit" | "collision" | "expired" | "closed";

export type FederationGrantIntentWrite =
	| { readonly outcome: "created" | "unchanged" }
	| { readonly outcome: "refused"; readonly reason: FederationGrantIntentRefusal };

export interface FederationGrantIntentStore {
	/** Non-empty; names the adapter in logs and diagnostics. */
	readonly kind: string;

	/**
	 * Admits an intent: reserves the bound's capacity and writes the record
	 * atomically (count-then-insert lets concurrent clients exceed the bound;
	 * insert-then-count leaves uncounted records behind a crash). Writing the
	 * same record again is `unchanged`, with no deadline extension and no second
	 * place, so core may retry a lost answer. Any other record under a resident
	 * handle is a `collision`, never replaced.
	 */
	putIntent(record: FederationGrantIntent, now: Date): Promise<FederationGrantIntentWrite>;

	/**
	 * The intent, if it is live: admitted, not answered, not finished, and not
	 * past its deadline on the caller's clock. A copy — what the caller does with
	 * it is not what the next caller reads.
	 */
	getIntent(handle: string, now: Date): Promise<FederationGrantIntent | null>;

	/**
	 * Parks a consent challenge for a live intent, bound to the asking browser,
	 * and returns the record the page will read. One challenge per intent: a
	 * repeat start from the same browser gets the parked one, deadline
	 * untouched. Another browser, or an intent that is not live, gets `null`;
	 * the route must not be able to tell those apart.
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
	 * Answers a challenge once, atomically: the challenge is removed, the intent
	 * spent, and an approval creates the transaction, or none of it happens
	 * (otherwise an accept and a deny could both apply, or a crash could consume
	 * a consent with nothing to continue). A denial releases its reserved
	 * capacity; an approval keeps it until {@link finishIntent}.
	 */
	answerConsent(input: {
		readonly challenge: string;
		readonly binding: FederationGrantBrowserBinding;
		readonly answer: FederationGrantConsentAnswer;
		readonly now: Date;
	}): Promise<FederationGrantConsentAnswerResult>;

	/**
	 * Reads and removes the callback's transaction atomically, so two callbacks
	 * cannot exchange one code, and only when it belongs to the connection the
	 * callback arrived on; another connection's transaction is left untouched.
	 */
	consumeTransaction(input: {
		readonly state: string;
		readonly connection: string;
		readonly now: Date;
	}): Promise<FederationGrantConnectTransaction | null>;

	/**
	 * Ends a flow: closes the handle, drops any consent or transaction left under
	 * it and releases its capacity, idempotently. Called after every terminal
	 * outcome, failures included. Never touches a grant: ending its pointer is
	 * `retireIntent`'s job.
	 */
	finishIntent(handle: string, now: Date): Promise<void>;
}

/**
 * `consent.at + lifetimeMs`, as an adapter computes it when recording an
 * approval: from the answer, never from the callback. Shared so both adapters
 * agree and no caller can hand a store its own expiry.
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
		 * Acquisition's records. Optional: a deployment that spends grants without
		 * issuing them needs none, and one with federation grants enabled is
		 * refused at boot without it.
		 */
		readonly federationGrantIntentStore?: FederationGrantIntentStore;
	}
}
