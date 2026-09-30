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
 * The federation grant intent store's client: acquisition's records under the `{intents}` hash
 * tag, each write one guarded script and each read a plain command.
 */

/**
 * What an intent admission answered. `unchanged` is the
 * retry of a write whose answer the caller lost: the same record, already
 * there, its deadline untouched and its place against the bound not taken
 * twice.
 */
export interface FederationGrantIntentAdmission {
	readonly outcome: "created" | "unchanged" | "refused";
	readonly reason?: "limit" | "collision" | "closed" | "expired";
}

/** What answering a consent did, with the record the answer applied to. */
export interface FederationGrantConsentAnswered {
	readonly outcome: "empty" | "denied" | "accepted" | "state_collision";
	/** The intent, for a denial; the transaction, for an approval. */
	readonly record?: string;
}

/**
 * Vendor-facing half of acquisition's records: semantic operations rather
 * than commands, because each one is a single guarded script.
 *
 * Every key one of these touches is derived inside the script from `prefix`,
 * which ends in the constant `{intents}` hash tag, so a script may reach the
 * consent an intent points at, or the transaction under a stored state,
 * without the caller naming a key it does not know yet, all in one Cluster
 * slot. Nothing here spans this keyspace and a grant's (`fg:{<id>}:…`).
 *
 * The records travel as text this package's codec produced. A driver neither
 * reads nor writes their fields; the scripts compare only the flat fields
 * beside them — a deadline, a binding, a connection, a pair — so no script
 * has to parse JSON to decide anything.
 */
export interface FederationGrantIntentStoreClient {
	/**
	 * Admits an intent: takes its place against the bound and writes the record,
	 * as one step. Prunes the bound's index on the SERVER's clock first, so a
	 * place is released by the passage of time and not by a caller.
	 */
	admitIntent(
		prefix: string,
		input: {
			readonly handle: string;
			readonly record: string;
			readonly expiresAtMs: number;
			readonly nowMs: number;
			/** Length-prefixed `(clientId, subject)`; the index this reservation belongs to. */
			readonly pair: string;
			/** Whether this intent takes a place at all — a reauthorization does not. */
			readonly counts: boolean;
			readonly limit: number;
			/** How long the index outlives its last member, so it never dies under one. */
			readonly reservationAllowanceMs: number;
		},
	): Promise<FederationGrantIntentAdmission>;

	/** The intent's text while it is live and the caller's clock is before its deadline. */
	readIntent(prefix: string, handle: string, nowMs: number): Promise<string | null>;

	/**
	 * Parks a challenge for a live intent, or hands back the one already parked
	 * for the same browser. A challenge another intent holds is never taken.
	 */
	parkConsent(
		prefix: string,
		input: {
			readonly handle: string;
			readonly challenge: string;
			readonly record: string;
			/** The browser this challenge is answerable from, as one comparable string. */
			readonly binding: string;
			readonly expiresAtMs: number;
			readonly nowMs: number;
		},
	): Promise<string | null>;

	/** The parked record, without spending it. */
	readConsent(prefix: string, challenge: string, nowMs: number): Promise<string | null>;

	/**
	 * Answers a challenge once: the challenge goes, the intent is spent, and an
	 * approval writes the transaction — or none of it happens. A denial releases
	 * the place against the bound; an approval keeps it until the flow ends.
	 */
	answerConsent(
		prefix: string,
		input: {
			readonly challenge: string;
			readonly binding: string;
			readonly nowMs: number;
			readonly decision: "accept" | "deny";
			readonly state?: string;
			readonly transaction?: string;
			readonly transactionExpiresAtMs?: number;
			readonly connection?: string;
		},
	): Promise<FederationGrantConsentAnswered>;

	/** Reads and removes the transaction, and only for the connection it belongs to. */
	consumeTransaction(
		prefix: string,
		input: {
			readonly state: string;
			readonly connection: string;
			readonly nowMs: number;
		},
	): Promise<string | null>;

	/** Closes the handle, drops what is left under it, releases its place — once. */
	finishIntent(prefix: string, handle: string, nowMs: number): Promise<void>;
}
