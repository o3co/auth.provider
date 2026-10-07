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
 * Redis {@link FederationGrantIntentStore}: acquisition's records, under one
 * hash tag of their own. See ADR
 * 2026-09-17-federation-grants-offline-delegation, D16.
 *
 * ```text
 * <prefix>{intents}:i:<handle>      HASH   the intent, its deadline, its pointers, and the marker a spent one leaves
 * <prefix>{intents}:c:<challenge>   HASH   the consent record and the browser it is answerable from
 * <prefix>{intents}:tx:<state>      HASH   the connect transaction and the connection it belongs to
 * <prefix>{intents}:r:<pair>        ZSET   one member per live first-time intent, scored by its deadline
 * ```
 *
 * **One tag, so one script can reach what it has to.** A script is given the
 * key it is routed by and derives the others — the consent an intent points at,
 * the transaction under a stored state — from the prefix. One slot makes that
 * legal on a Cluster, and makes each operation of the port one atomic step
 * rather than two commands with a race between them.
 *
 * **Nothing spans this keyspace and a grant's** (`<prefix>{<id>}:grant`):
 * supersession is settled by the grant's own current-intent pointer, and
 * core — not an adapter — orders the two writes an acquisition makes.
 *
 * **The bound is an index, not a counter.** A counter would have to be
 * decremented by whoever finished, and a flow that never came back would stay
 * counted for ever. Members scored by their deadline are dropped by
 * `ZREMRANGEBYSCORE` on the SERVER's clock; the index's own deadline is its
 * last member's plus an allowance, so it never expires under a reservation it
 * still holds.
 *
 * **Two clocks.** What a caller is told is judged on the `now` it passes; what
 * is reclaimed is judged by Redis — the key TTLs, and the server time the
 * admission script reads. No script deletes a record because a caller's clock
 * says it has lapsed.
 */

import {
	defineModule,
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
	isStorableLifetime,
} from "@o3co/auth-provider-core";
import { z } from "zod";
import type { FederationGrantIntentStoreClient } from "./clients.mjs";
import {
	decodeFederationGrantConsent,
	decodeFederationGrantIntent,
	decodeFederationGrantTransaction,
	encodeFederationGrantConsent,
	encodeFederationGrantIntent,
	encodeFederationGrantTransaction,
	federationGrantBindingText,
	federationGrantIntentPairText,
} from "./internal/federation-grant-intent-codec.mjs";
import { redisReference } from "./internal/section.mjs";

/**
 * How long the bound's index outlives its last reservation. It is not a grace
 * period for the reservation itself — `ZREMRANGEBYSCORE` drops that on its
 * deadline — only insurance that the key holding the index does not expire
 * while a member is still in it.
 */
export const FEDERATION_GRANT_RESERVATION_ALLOWANCE_MS = 5 * 60_000;

export interface RedisFederationGrantIntentStoreOptions {
	readonly client: FederationGrantIntentStoreClient;
	/** Outer namespace, shared with the grant store's. The `{intents}` tag follows it. Default `fg:`. */
	readonly keyPrefix?: string;
	/** See {@link FEDERATION_GRANT_RESERVATION_ALLOWANCE_MS}. */
	readonly reservationAllowanceMs?: number;
}

const RANGE = (what: string): RangeError =>
	new RangeError(`federation grant intent store: ${what}`);

const instant = (value: Date, name: string): number => {
	const ms = value?.getTime?.();
	if (typeof ms !== "number" || Number.isNaN(ms)) throw RANGE(`${name} must be a date`);
	return ms;
};

/**
 * A value inside a key name: base64url of its JSON, as the grant store encodes
 * an ID. No caller-supplied text can then carry a brace into the hash tag, and
 * two values differing only in a lone surrogate cannot collide.
 */
const keyPart = (value: string): string =>
	Buffer.from(JSON.stringify(value), "utf8").toString("base64url");

export function createRedisFederationGrantIntentStore(
	options: RedisFederationGrantIntentStoreOptions,
): FederationGrantIntentStore {
	const keyPrefix = options.keyPrefix ?? "fg:";
	if (keyPrefix.includes("{") || keyPrefix.includes("}")) {
		// A brace in the prefix would open a hash tag of its own, and these keys
		// would stop sharing a slot — which is what every script here depends on.
		throw RANGE("keyPrefix must not contain a brace");
	}
	// It must end within the Date range (core's `isStorableLifetime`): the
	// admission's script reserves the place and sets the index's deadline last,
	// so a deadline Redis refuses leaves the reservation index with no TTL.
	const allowance = options.reservationAllowanceMs ?? FEDERATION_GRANT_RESERVATION_ALLOWANCE_MS;
	if (!isStorableLifetime(allowance, { allowZero: true })) {
		throw RANGE(
			"reservationAllowanceMs must be a non-negative number of milliseconds that ends within the Date range",
		);
	}
	const prefix = `${keyPrefix}{intents}:`;
	const client = options.client;

	const readIntent = async (
		handle: string,
		nowMs: number,
	): Promise<FederationGrantIntent | null> => {
		const text = await client.readIntent(prefix, keyPart(handle), nowMs);
		return text === null ? null : decodeFederationGrantIntent(text);
	};

	const readConsent = async (
		challenge: string,
		nowMs: number,
	): Promise<FederationGrantConsentRecord | null> => {
		const text = await client.readConsent(prefix, keyPart(challenge), nowMs);
		return text === null ? null : decodeFederationGrantConsent(text);
	};

	return {
		kind: "redis",

		async putIntent(record, now): Promise<FederationGrantIntentWrite> {
			const nowMs = instant(now, "now");
			instant(record.createdAt, "createdAt");
			const expiresAtMs = instant(record.expiresAt, "expiresAt");
			const admitted = await client.admitIntent(prefix, {
				handle: keyPart(record.handle),
				record: encodeFederationGrantIntent(record),
				expiresAtMs,
				nowMs,
				pair: keyPart(federationGrantIntentPairText(record.clientId, record.subject)),
				counts: record.kind === "initial",
				limit: FEDERATION_GRANT_FIRST_INTENTS_PER_CLIENT_SUBJECT_LIMIT,
				reservationAllowanceMs: allowance,
			});
			if (admitted.outcome !== "refused") return { outcome: admitted.outcome };
			return { outcome: "refused", reason: admitted.reason ?? "collision" };
		},

		async getIntent(handle, now) {
			return await readIntent(handle, instant(now, "now"));
		},

		async parkConsent({ handle, challenge, binding, now }) {
			const nowMs = instant(now, "now");
			const intent = await readIntent(handle, nowMs);
			if (intent === null) return null;
			// The record the script will write if nothing is parked yet. When one is,
			// it hands back that one instead and this text is never stored.
			const record: FederationGrantConsentRecord = {
				challenge,
				intentHandle: handle,
				binding: { sessionId: binding.sessionId, sid: binding.sid, subject: binding.subject },
				scopes: [...intent.scopes],
				lifetimeMs: intent.lifetimeMs,
				createdAt: new Date(nowMs),
				// The one deadline: the intent's. Parking never extends it.
				expiresAt: new Date(intent.expiresAt),
			};
			const text = await client.parkConsent(prefix, {
				handle: keyPart(handle),
				challenge: keyPart(challenge),
				record: encodeFederationGrantConsent(record),
				binding: federationGrantBindingText(binding),
				expiresAtMs: intent.expiresAt.getTime(),
				nowMs,
			});
			return text === null ? null : decodeFederationGrantConsent(text);
		},

		async getConsent(challenge, now) {
			return await readConsent(challenge, instant(now, "now"));
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

			// The script is the one that judges: the binding, both deadlines,
			// whether the intent is still live. Nothing here decides any of that
			// first — a check made outside the script would be the one a test
			// exercises, and the script's own, which is the one a race meets,
			// would never be reached.
			if (answer.decision === "deny") {
				const answered = await client.answerConsent(prefix, {
					challenge: keyPart(challenge),
					binding: federationGrantBindingText(binding),
					nowMs,
					decision: "deny",
				});
				if (answered.outcome !== "denied" || answered.record === undefined) {
					return { outcome: "empty" };
				}
				return { outcome: "denied", intent: decodeFederationGrantIntent(answered.record) };
			}

			// An approval needs what the consent showed and the intent it spends,
			// to build the transaction the script writes. Read, not judged: if the
			// browser is the wrong one, the script refuses and this is discarded.
			const parked = await readConsent(challenge, nowMs);
			if (parked === null) return { outcome: "empty" };
			const intent = await readIntent(parked.intentHandle, nowMs);
			if (intent === null) return { outcome: "empty" };

			// Built here and written by the script, so that `consent.at` is the
			// answer's instant and the grant's expiry is derived from it — neither
			// is a later step's to choose. The intent is immutable, so the
			// snapshot cannot go stale between the read above and the write; what
			// can change is whether the intent is still answerable, and that the
			// script checks again for itself.
			const transaction: FederationGrantConnectTransaction = {
				state: answer.state,
				intent,
				binding: { sessionId: binding.sessionId, sid: binding.sid, subject: binding.subject },
				codeVerifier: answer.codeVerifier,
				nonce: answer.nonce,
				consent: { at: new Date(nowMs), sid: binding.sid, scopes: [...parked.scopes] },
				grantExpiresAt: federationGrantConsentExpiry(new Date(nowMs), parked.lifetimeMs),
				createdAt: new Date(nowMs),
				expiresAt: new Date(intent.expiresAt),
			};
			const answered = await client.answerConsent(prefix, {
				challenge: keyPart(challenge),
				binding: federationGrantBindingText(binding),
				nowMs,
				decision: "accept",
				state: keyPart(answer.state),
				transaction: encodeFederationGrantTransaction(transaction),
				transactionExpiresAtMs: intent.expiresAt.getTime(),
				connection: intent.connection,
			});
			if (answered.outcome === "state_collision") {
				return { outcome: "refused", reason: "state_collision" };
			}
			if (answered.outcome !== "accepted" || answered.record === undefined) {
				return { outcome: "empty" };
			}
			return {
				outcome: "accepted",
				transaction: decodeFederationGrantTransaction(answered.record),
			};
		},

		async consumeTransaction({ state, connection, now }) {
			const nowMs = instant(now, "now");
			const text = await client.consumeTransaction(prefix, {
				state: keyPart(state),
				connection,
				nowMs,
			});
			return text === null ? null : decodeFederationGrantTransaction(text);
		},

		async finishIntent(handle, now) {
			await client.finishIntent(prefix, keyPart(handle), instant(now, "now"));
		},
	};
}

// --- configuration --------------------------------------------------------

/**
 * The schema of `redis-federation-grant-intent-store {}`, the module's own
 * section: the key prefix acquisition's records live under
 * (`<prefix>{intents}:…`), strict. The flow budget and the bound are constants
 * on the port. It fills the prefix the package's `config/reference.conf` also
 * ships: {@link resolveRedisFederationGrantIntentStoreOptions} parses a
 * section as an operator wrote it, with no reference.conf beneath.
 */
export const redisFederationGrantIntentStoreSectionSchema = z
	.object({ keyPrefix: z.string().default("fg:") })
	.strict()
	.default(() => ({ keyPrefix: "fg:" }));

/** The options the adapter takes, from its section as an operator wrote it, parsed here. */
export function resolveRedisFederationGrantIntentStoreOptions(
	section: unknown,
): Omit<RedisFederationGrantIntentStoreOptions, "client"> {
	return { keyPrefix: redisFederationGrantIntentStoreSectionSchema.parse(section).keyPrefix };
}

/**
 * `defineModule` manifest for the Redis federation grant intent store. Its
 * own module, beside the grant store's, because a
 * deployment may keep grants in Redis and acquisition in memory on a single
 * replica — losing flows in progress on a restart and nothing else — and the
 * two are installed independently. The client is the composition root's to
 * provide, as the grant store's is; it may be the same connection. Its key
 * prefix is its own section's, `redis-federation-grant-intent-store.keyPrefix`,
 * apart from the grant store's: a deployment that moves one moves the other
 * too.
 */
export const redisFederationGrantIntentStoreModule = defineModule({
	name: "redis-federation-grant-intent-store",
	section: {
		schema: redisFederationGrantIntentStoreSectionSchema,
		reference: redisReference(),
	},
	requires: ["federationGrantIntentStoreClient"] as const,
	provides: {
		federationGrantIntentStore: ({ section, federationGrantIntentStoreClient }) =>
			createRedisFederationGrantIntentStore({
				client: federationGrantIntentStoreClient,
				...resolveRedisFederationGrantIntentStoreOptions(section),
			}),
	},
});
