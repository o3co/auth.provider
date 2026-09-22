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
 * In-process {@link FederationGrantIntentStore} (#593, D16, slice 6).
 *
 * Dev, test and single-replica only: what it holds is one browser's flow — a
 * PKCE verifier, a nonce, the consent challenge — so a second replica answers
 * every callback the first one started with "unknown transaction", and a
 * restart loses flows in flight. It loses no established grant, which is why
 * this adapter beside a durable grant store is permitted for a single replica
 * and refused by name under `deployment.mode = "multi"`.
 *
 * Every transition below is one synchronous critical section taken before the
 * promise resolves: the operations this port makes atomic are atomic here
 * because nothing awaits inside them.
 */

import {
	FEDERATION_GRANT_FIRST_INTENTS_PER_CLIENT_SUBJECT_LIMIT,
	type FederationGrantBrowserBinding,
	type FederationGrantConnectTransaction,
	type FederationGrantConsentAnswer,
	type FederationGrantConsentAnswerResult,
	type FederationGrantConsentRecord,
	type FederationGrantIntent,
	type FederationGrantIntentStore,
	type FederationGrantIntentWrite,
	federationGrantConsentExpiry,
} from "./intentStore.mjs";

/**
 * Sweep once this many entries are resident, and again each time that has
 * doubled: a connect the user never finishes leaves an entry nobody reads
 * again, under a handle nobody lodges again, and reclaiming on touch alone
 * would keep every one of them. Amortized, with no timer of its own, as the
 * grant store's and the pending-consent store's are.
 */
export const MEMORY_FEDERATION_GRANT_INTENT_STORE_SWEEP_FLOOR = 1024;

/** In-process intent store, with what is resident exposed for observability. */
export interface MemoryFederationGrantIntentStore extends FederationGrantIntentStore {
	/** Entries currently resident, reclaimable-but-unreclaimed included. */
	readonly size: number;
	/**
	 * Whether anything is THERE under the handle — a live record or the marker a
	 * spent one leaves. What makes a handle taken, which is not the same as what
	 * a caller can see.
	 */
	holdsIntent(handle: string): boolean;
	holdsConsent(challenge: string): boolean;
	/** Whether the transaction — and with it its verifier and nonce — is still held. */
	holdsTransaction(state: string): boolean;
	/** Reservations against the bound for the pair, on this store's own clock. */
	reservations(clientId: string, subject: string): number;
}

/**
 * The instant as a number. An invalid date is refused, and not compared: every
 * comparison with NaN is false, so a rule phrased "is it still before?" would
 * read an invalid `now` as "everything has lapsed".
 */
function instant(date: Date, name: string): number {
	const ms = date.getTime();
	if (Number.isNaN(ms)) {
		throw new RangeError(`FederationGrantIntentStore: ${name} is not a valid date`);
	}
	return ms;
}

interface Entry {
	/** The record as admitted. Kept past the answer, as the marker of a spent handle. */
	readonly record: FederationGrantIntent;
	/** `false` once the intent was answered or finished: nothing may activate through it again. */
	live: boolean;
	/** Whether this entry still holds a place against the bound. */
	reserved: boolean;
	/** The challenge parked for it, while there is one. */
	challenge: string | null;
	/** The transaction an approval created, while it is unconsumed. */
	state: string | null;
}

const pairKey = (clientId: string, subject: string): string =>
	// Length-prefixed: two pairs whose parts differ only in where a separator
	// falls must not share a bucket.
	`${clientId.length}:${clientId}:${subject.length}:${subject}`;

function copyBinding(from: FederationGrantBrowserBinding): FederationGrantBrowserBinding {
	return { sessionId: from.sessionId, sid: from.sid, subject: from.subject };
}

/**
 * Field by field, and not a spread: what is stored is the intent and nothing a
 * caller's object happens to carry beside it. Dates and collections are copied,
 * so a caller that changes what it wrote or what it read changes nothing here.
 */
function copyIntent(from: FederationGrantIntent): FederationGrantIntent {
	return {
		handle: from.handle,
		kind: from.kind,
		grantId: from.grantId,
		clientId: from.clientId,
		subject: from.subject,
		connection: from.connection,
		federation: from.federation,
		identityRevision: from.identityRevision,
		authorizationRevision: from.authorizationRevision,
		callbackUri: from.callbackUri,
		scopes: [...from.scopes],
		...(from.resource !== undefined ? { resource: from.resource } : {}),
		authorizationParams: { ...from.authorizationParams },
		redirectUri: from.redirectUri,
		clientState: from.clientState,
		...(from.upstreamSubject !== undefined ? { upstreamSubject: from.upstreamSubject } : {}),
		lifetimeMs: from.lifetimeMs,
		createdAt: new Date(from.createdAt),
		expiresAt: new Date(from.expiresAt),
		correlationId: from.correlationId,
	};
}

function copyConsent(from: FederationGrantConsentRecord): FederationGrantConsentRecord {
	return {
		challenge: from.challenge,
		intentHandle: from.intentHandle,
		binding: copyBinding(from.binding),
		scopes: [...from.scopes],
		lifetimeMs: from.lifetimeMs,
		createdAt: new Date(from.createdAt),
		expiresAt: new Date(from.expiresAt),
	};
}

function copyTransaction(
	from: FederationGrantConnectTransaction,
): FederationGrantConnectTransaction {
	return {
		state: from.state,
		intent: copyIntent(from.intent),
		binding: copyBinding(from.binding),
		codeVerifier: from.codeVerifier,
		nonce: from.nonce,
		consent: {
			at: new Date(from.consent.at),
			sid: from.consent.sid,
			scopes: [...from.consent.scopes],
		},
		grantExpiresAt: new Date(from.grantExpiresAt),
		createdAt: new Date(from.createdAt),
		expiresAt: new Date(from.expiresAt),
	};
}

/** Whether two records are the same one, for the retry `putIntent` answers `unchanged`. */
function sameIntent(a: FederationGrantIntent, b: FederationGrantIntent): boolean {
	const asKey = (record: FederationGrantIntent): string =>
		JSON.stringify([
			record.handle,
			record.kind,
			record.grantId,
			record.clientId,
			record.subject,
			record.connection,
			record.federation,
			record.identityRevision,
			record.authorizationRevision,
			record.callbackUri,
			[...record.scopes],
			record.resource ?? null,
			Object.entries(record.authorizationParams).sort(([left], [right]) =>
				left < right ? -1 : left > right ? 1 : 0,
			),
			record.redirectUri,
			record.clientState,
			record.upstreamSubject ?? null,
			record.lifetimeMs,
			record.createdAt.getTime(),
			record.expiresAt.getTime(),
			record.correlationId,
		]);
	return asKey(a) === asKey(b);
}

const bindingsMatch = (
	a: FederationGrantBrowserBinding,
	b: FederationGrantBrowserBinding,
): boolean => a.sessionId === b.sessionId && a.sid === b.sid && a.subject === b.subject;

export function createMemoryFederationGrantIntentStore(): MemoryFederationGrantIntentStore {
	const entries = new Map<string, Entry>();
	const consents = new Map<string, FederationGrantConsentRecord>();
	const transactions = new Map<string, FederationGrantConnectTransaction>();
	let sweepAt = MEMORY_FEDERATION_GRANT_INTENT_STORE_SWEEP_FLOOR;

	/**
	 * Reclamation, on this store's own clock and never on a caller's: an entry
	 * whose deadline has passed here is gone with whatever is left under it, and
	 * its place against the bound with it.
	 */
	const reclaim = (handle: string, entry: Entry): void => {
		entries.delete(handle);
		if (entry.challenge !== null) consents.delete(entry.challenge);
		if (entry.state !== null) transactions.delete(entry.state);
	};

	const sweep = (): void => {
		const now = Date.now();
		for (const [handle, entry] of entries) {
			if (entry.record.expiresAt.getTime() <= now) reclaim(handle, entry);
		}
		sweepAt = Math.max(MEMORY_FEDERATION_GRANT_INTENT_STORE_SWEEP_FLOOR, entries.size * 2);
	};

	/** What is resident here, after this store's own clock has had its say. */
	const resident = (handle: string): Entry | undefined => {
		const entry = entries.get(handle);
		if (entry === undefined) return undefined;
		if (entry.record.expiresAt.getTime() <= Date.now()) {
			reclaim(handle, entry);
			return undefined;
		}
		return entry;
	};

	/** Resident, live, and not past the deadline the CALLER passed. */
	const visible = (handle: string, nowMs: number): Entry | undefined => {
		const entry = resident(handle);
		if (entry === undefined || !entry.live) return undefined;
		return nowMs < entry.record.expiresAt.getTime() ? entry : undefined;
	};

	const countReservations = (clientId: string, subject: string): number => {
		const key = pairKey(clientId, subject);
		let held = 0;
		for (const [handle, entry] of entries) {
			if (!entry.reserved) continue;
			if (entry.record.expiresAt.getTime() <= Date.now()) {
				reclaim(handle, entry);
				continue;
			}
			if (pairKey(entry.record.clientId, entry.record.subject) === key) held += 1;
		}
		return held;
	};

	/** Ends an intent, whichever way it ended: the marker stays, everything else goes. */
	const close = (entry: Entry, options: { readonly release: boolean }): void => {
		entry.live = false;
		if (entry.challenge !== null) {
			consents.delete(entry.challenge);
			entry.challenge = null;
		}
		if (options.release) {
			entry.reserved = false;
			if (entry.state !== null) {
				transactions.delete(entry.state);
				entry.state = null;
			}
		}
	};

	return {
		kind: "memory",

		get size() {
			return entries.size;
		},

		holdsIntent(handle) {
			return resident(handle) !== undefined;
		},

		holdsConsent(challenge) {
			const record = consents.get(challenge);
			if (record === undefined) return false;
			// Read through the intent, so that a challenge whose intent this
			// store's clock has reclaimed does not read as held.
			return resident(record.intentHandle) !== undefined;
		},

		holdsTransaction(state) {
			const transaction = transactions.get(state);
			if (transaction === undefined) return false;
			return resident(transaction.intent.handle) !== undefined;
		},

		reservations(clientId, subject) {
			return countReservations(clientId, subject);
		},

		async putIntent(record, now): Promise<FederationGrantIntentWrite> {
			const nowMs = instant(now, "now");
			instant(record.createdAt, "createdAt");
			const expiresAtMs = instant(record.expiresAt, "expiresAt");
			if (entries.size >= sweepAt) sweep();

			// Residency before visibility: a handle is taken for as long as a
			// record is there under it, not for as long as a caller can see it.
			const existing = resident(record.handle);
			if (existing !== undefined) {
				if (!existing.live) return { outcome: "refused", reason: "closed" };
				return sameIntent(existing.record, record)
					? { outcome: "unchanged" }
					: { outcome: "refused", reason: "collision" };
			}

			if (!(nowMs < expiresAtMs)) return { outcome: "refused", reason: "expired" };

			const counts = record.kind === "initial";
			if (
				counts &&
				countReservations(record.clientId, record.subject) >=
					FEDERATION_GRANT_FIRST_INTENTS_PER_CLIENT_SUBJECT_LIMIT
			) {
				return { outcome: "refused", reason: "limit" };
			}

			entries.set(record.handle, {
				record: copyIntent(record),
				live: true,
				reserved: counts,
				challenge: null,
				state: null,
			});
			return { outcome: "created" };
		},

		async getIntent(handle, now) {
			const nowMs = instant(now, "now");
			const entry = visible(handle, nowMs);
			return entry === undefined ? null : copyIntent(entry.record);
		},

		async parkConsent({ handle, challenge, binding, now }) {
			const nowMs = instant(now, "now");
			const entry = visible(handle, nowMs);
			if (entry === undefined) return null;

			if (entry.challenge !== null) {
				const parked = consents.get(entry.challenge);
				if (parked === undefined) return null;
				// One challenge per intent: the browser that parked it is given the
				// same one back, with its deadline untouched. Any other browser is
				// told nothing, which is what an intent that is not live is told too.
				return bindingsMatch(parked.binding, binding) ? copyConsent(parked) : null;
			}
			// A challenge another intent is holding is never overwritten. At 256
			// bits this is a fault, not a collision to recover from; the caller
			// gets nothing and the flow starts again.
			if (consents.has(challenge)) return null;

			const record: FederationGrantConsentRecord = {
				challenge,
				intentHandle: handle,
				binding: copyBinding(binding),
				scopes: [...entry.record.scopes],
				lifetimeMs: entry.record.lifetimeMs,
				createdAt: new Date(nowMs),
				// The one deadline: the intent's. Parking never extends it.
				expiresAt: new Date(entry.record.expiresAt),
			};
			consents.set(challenge, record);
			entry.challenge = challenge;
			return copyConsent(record);
		},

		async getConsent(challenge, now) {
			const nowMs = instant(now, "now");
			const record = consents.get(challenge);
			if (record === undefined) return null;
			if (resident(record.intentHandle) === undefined) return null;
			return nowMs < record.expiresAt.getTime() ? copyConsent(record) : null;
		},

		async answerConsent({
			challenge,
			binding,
			answer,
			now,
		}: {
			readonly challenge: string;
			readonly binding: FederationGrantBrowserBinding;
			readonly answer: FederationGrantConsentAnswer;
			readonly now: Date;
		}): Promise<FederationGrantConsentAnswerResult> {
			const nowMs = instant(now, "now");
			const record = consents.get(challenge);
			if (record === undefined) return { outcome: "empty" };
			if (!(nowMs < record.expiresAt.getTime())) return { outcome: "empty" };
			if (!bindingsMatch(record.binding, binding)) return { outcome: "empty" };

			const entry = visible(record.intentHandle, nowMs);
			if (entry === undefined) return { outcome: "empty" };

			if (answer.decision === "accept" && transactions.has(answer.state)) {
				// Nothing is spent: this is a fault on this side, and the user's link
				// has not expired.
				return { outcome: "refused", reason: "state_collision" };
			}

			const intent = copyIntent(entry.record);
			if (answer.decision === "deny") {
				close(entry, { release: true });
				return { outcome: "denied", intent };
			}

			const transaction: FederationGrantConnectTransaction = {
				state: answer.state,
				intent,
				binding: copyBinding(binding),
				codeVerifier: answer.codeVerifier,
				nonce: answer.nonce,
				consent: { at: new Date(nowMs), sid: binding.sid, scopes: [...record.scopes] },
				// Dated here, by the store, at the answer: the grant's expiry is not
				// the callback's to choose, and a caller cannot hand one in (D3).
				grantExpiresAt: federationGrantConsentExpiry(new Date(nowMs), record.lifetimeMs),
				createdAt: new Date(nowMs),
				expiresAt: new Date(entry.record.expiresAt),
			};
			// The approval keeps its place against the bound: the flow is still
			// running, and the record the callback will activate is still to be
			// written.
			close(entry, { release: false });
			transactions.set(answer.state, transaction);
			entry.state = answer.state;
			return { outcome: "accepted", transaction: copyTransaction(transaction) };
		},

		async consumeTransaction({ state, connection, now }) {
			const nowMs = instant(now, "now");
			const transaction = transactions.get(state);
			if (transaction === undefined) return null;
			if (resident(transaction.intent.handle) === undefined) return null;
			// Hidden, not reclaimed: a caller's clock does not delete a record.
			if (!(nowMs < transaction.expiresAt.getTime())) return null;
			// A callback on another connection's path spends nothing.
			if (transaction.intent.connection !== connection) return null;

			transactions.delete(state);
			const entry = entries.get(transaction.intent.handle);
			if (entry !== undefined && entry.state === state) entry.state = null;
			return copyTransaction(transaction);
		},

		async finishIntent(handle, now) {
			instant(now, "now");
			const entry = resident(handle);
			if (entry === undefined) return;
			// Idempotent: the release happens on the entry's own flag, so a second
			// call frees nothing a third time.
			close(entry, { release: true });
		},
	};
}
