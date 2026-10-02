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
	type AdapterBuilder,
	type CreateUserSessionInput,
	checkSecondFactorEvent,
	consoleLogger,
	expectsRenewalNonce,
	isRenewalNonce,
	type Logger,
	loggableError,
	readEnrollmentFacts,
	readRenewalNonces,
	recordableAuthTime,
	recordableEnrollmentFacts,
	recordableSessionAuthentication,
	type SessionAuthentication,
	type SessionEnrollmentFacts,
	type SupportsSecondFactorUpdate,
	sessionAfterSecondFactor,
	type UserSession,
	type UserSessionClaims,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import type { UserSessionStoreClient } from "./clients.mjs";

export interface RedisUserSessionStoreOptions {
	readonly client: UserSessionStoreClient;
	readonly keyPrefix: string;
	/**
	 * Where `get()` reports a stored envelope that fails JSON.parse or shape
	 * validation: one `user_session_corrupt_envelope` warn, `reason`
	 * `json_parse` (with the parser's projection as `err`) or
	 * `shape_invalid`. `redisSessionStoresModule` passes the composition's
	 * `logger` slot; absent, `consoleLogger`. The read is refused (`null`)
	 * either way.
	 */
	readonly logger?: Logger;
}

/**
 * `UserSession.authentication` as the envelope stores it: `mfaAt` as epoch
 * milliseconds, like every other instant here. A field that
 * holds `undefined` is left out by `JSON.stringify`.
 */
interface EnvelopeAuthentication {
	primary: string;
	federation: string | undefined;
	upstreamAmr: string[] | undefined;
	mfaAtMs: number | undefined;
}

interface Envelope {
	sid: string;
	sub: string;
	authTimeMs: number;
	createdAtMs: number;
	expiresAtMs: number;
	claims: Record<string, unknown>;
	/**
	 * RFC 8176 values recorded by the login path. A required key, `undefined`
	 * when there are none, which `JSON.stringify` leaves out.
	 */
	amr: string[] | undefined;
	/**
	 * How the session was established. Absent in an envelope an older release
	 * wrote (an older release also reads envelopes that have it, its shape
	 * check ignoring the key), and read as `undefined`: a session
	 * `sessionAuthentication` splits as it reads it.
	 */
	authentication: EnvelopeAuthentication | undefined;
	/**
	 * What the login's `User` said for a first binding, as the two facts.
	 * Left out when none was recorded, and absent in an envelope an older
	 * release wrote (which also reads one that has it, ignoring the key).
	 */
	enrollmentFacts?: SessionEnrollmentFacts;
	/**
	 * The renewal nonce the last escalation carried (the MFA ADR's D27). Left
	 * out until one is recorded, and absent in an envelope an older release
	 * wrote (which also reads one that has it, ignoring the key).
	 */
	renewalNonce?: string;
}

/**
 * Maximum representable date in milliseconds (`new Date(8_640_000_000_000_000)`
 * is the upper bound of valid JavaScript Date values per ECMA-262 §21.4.1.1).
 * Values outside `[0, MAX_DATE_MS]` cannot survive a `new Date(ms)` round-trip
 * — they produce `Invalid Date` whose `getTime()` returns `NaN`.
 */
const MAX_DATE_MS = 8_640_000_000_000_000;

/**
 * Per-field timestamp predicate: a non-negative safe integer within the Date
 * range. `Number.isFinite` is not enough: a very large finite number (past
 * 2^53, or `Number.MAX_VALUE`) loses precision and may give an Invalid Date,
 * and `expiresAtMs <= Date.now()` could then be `false` for an envelope that
 * effectively never expires, silently bypassing the expiry check. Negative
 * values are refused: a session timestamp is never before 1970.
 */
const isValidTimestamp = (x: unknown): x is number =>
	typeof x === "number" && Number.isSafeInteger(x) && x >= 0 && x <= MAX_DATE_MS;

const isStringList = (x: unknown): x is string[] =>
	Array.isArray(x) && x.every((v) => typeof v === "string");

/**
 * `authentication` is absent, or well-formed: a non-empty string primary —
 * what `create` admits — and each other field absent or of its type. `null`
 * is neither — this store never writes one — and an envelope holding it is
 * refused rather than read as a session from before the key, which would
 * split it again and forget a verified second factor.
 */
const isValidEnvelopeAuthentication = (v: unknown): v is EnvelopeAuthentication | undefined => {
	if (v === undefined) return true;
	if (typeof v !== "object" || v === null || Array.isArray(v)) return false;
	const a = v as Partial<EnvelopeAuthentication>;
	return (
		typeof a.primary === "string" &&
		a.primary.length > 0 &&
		(a.federation === undefined || typeof a.federation === "string") &&
		(a.upstreamAmr === undefined || isStringList(a.upstreamAmr)) &&
		(a.mfaAtMs === undefined || isValidTimestamp(a.mfaAtMs))
	);
};

/**
 * Hand-rolled type predicate for `Envelope`, lighter than Zod for the storage
 * layer. A cast is not enough: for an `expiresAtMs` of `undefined` or `NaN`,
 * `expiresAtMs <= Date.now()` is `false`, which would bypass the expiry check
 * and return a session with Invalid Date fields. `claims` must be a plain
 * object; `[]` and `null` both fail, the fail-closed default for a
 * security-critical path.
 */
const isValidEnvelope = (v: unknown): v is Envelope => {
	if (typeof v !== "object" || v === null) return false;
	const e = v as Partial<Envelope>;
	return (
		typeof e.sid === "string" &&
		typeof e.sub === "string" &&
		isValidTimestamp(e.authTimeMs) &&
		isValidTimestamp(e.createdAtMs) &&
		isValidTimestamp(e.expiresAtMs) &&
		typeof e.claims === "object" &&
		e.claims !== null &&
		!Array.isArray(e.claims) &&
		(e.amr === undefined || isStringList(e.amr)) &&
		isValidEnvelopeAuthentication(e.authentication) &&
		// Absent, or the two facts: anything else is corrupt, never read as none.
		(e.enrollmentFacts === undefined || readEnrollmentFacts(e.enrollmentFacts) !== undefined) &&
		// Absent, or a nonce: anything else is corrupt, never read as unbound.
		(e.renewalNonce === undefined || isRenewalNonce(e.renewalNonce))
	);
};

const toEnvelopeAuthentication = (a: SessionAuthentication): EnvelopeAuthentication => ({
	primary: a.primary,
	federation: a.federation,
	upstreamAmr: a.upstreamAmr ? [...a.upstreamAmr] : undefined,
	mfaAtMs: a.mfaAt?.getTime(),
});

/** Every field named, those holding `undefined` included, as the session's type requires. */
const fromEnvelopeAuthentication = (a: EnvelopeAuthentication): SessionAuthentication => ({
	primary: a.primary,
	federation: a.federation,
	upstreamAmr: a.upstreamAmr ? [...a.upstreamAmr] : undefined,
	mfaAt: a.mfaAtMs === undefined ? undefined : new Date(a.mfaAtMs),
});

const toEnvelope = (input: CreateUserSessionInput, createdAtMs: number): Envelope => ({
	sid: input.sid,
	sub: input.sub,
	authTimeMs: input.authTime.getTime(),
	createdAtMs,
	expiresAtMs: input.expiresAt.getTime(),
	claims: { ...input.claims },
	amr: input.amr ? [...input.amr] : undefined,
	authentication: input.authentication ? toEnvelopeAuthentication(input.authentication) : undefined,
	...(input.enrollmentFacts === undefined
		? {}
		: {
				enrollmentFacts: {
					witness: input.enrollmentFacts.witness,
					mailAddress: input.enrollmentFacts.mailAddress,
				},
			}),
});

const fromEnvelope = (e: Envelope): UserSession => ({
	sid: e.sid,
	sub: e.sub,
	authTime: new Date(e.authTimeMs),
	createdAt: new Date(e.createdAtMs),
	expiresAt: new Date(e.expiresAtMs),
	claims: { ...e.claims } as UserSessionClaims,
	amr: e.amr ? [...e.amr] : undefined,
	authentication: e.authentication ? fromEnvelopeAuthentication(e.authentication) : undefined,
	// Checked by `isValidEnvelope`; copied to the two facts.
	...(e.enrollmentFacts === undefined
		? {}
		: { enrollmentFacts: readEnrollmentFacts(e.enrollmentFacts) }),
	...(e.renewalNonce === undefined ? {} : { renewalNonce: e.renewalNonce }),
});

/**
 * How many times `recordSecondFactor` re-reads after losing its
 * compare-and-set before it gives up. A loss means another write moved this
 * one session in between — another step-up in flight on it — so a handful
 * covers every real race; past it the caller sees an error, as for an outage.
 */
const RECORD_SECOND_FACTOR_ATTEMPTS = 5;

/**
 * Redis-backed UserSessionStore, with the step-up capability.
 *
 * Each session is one string key `${keyPrefix}${sid}` holding a JSON envelope,
 * its TTL set by `SET PX`. There is no lost-update window: the one write after
 * `create` is `recordSecondFactor`, which replaces the envelope only while it
 * still holds what was read.
 *
 * - `create`: `SET NX PX`, an atomic insert-only write. `PX` is whole
 *   milliseconds because a Date is; an Invalid Date is a RangeError before
 *   Redis is asked.
 * - `get`: one `GET`. The envelope carries `expiresAtMs`, so no `PTTL` is
 *   needed; the TTL deletes the key eventually.
 * - `recordSecondFactor`: reads, computes the next envelope with core's
 *   `sessionAfterSecondFactor` (which first splits a session recorded without
 *   `authentication`), and writes it with the client's `replaceIfUnchanged`
 *   (`KEEPTTL`, only while the stored bytes are the ones read), re-reading on
 *   a loss at most {@link RECORD_SECOND_FACTOR_ATTEMPTS} times, and answering
 *   `null` when the envelope read holds a renewal nonce the event does not
 *   expect (`expectsRenewalNonce`). Only `amr`, the
 *   `authentication` fields this release knows, and `renewalNonce` when the
 *   event carries one are rewritten; everything
 *   else, keys a newer release added included, is written back as read, so a
 *   step-up on a replica not yet upgraded loses nothing a newer one recorded.
 * - `delete`: `DEL`.
 *
 * A client without `replaceIfUnchanged` is refused here, naming the method,
 * rather than failing the first step-up.
 * See the MFA ADR (2026-09-25-multi-factor-authentication), D9.
 */
export function createRedisUserSessionStore(
	opts: RedisUserSessionStoreOptions,
): UserSessionStore & SupportsSecondFactorUpdate {
	if (typeof (opts.client as Partial<UserSessionStoreClient>)?.replaceIfUnchanged !== "function") {
		throw new TypeError(
			"createRedisUserSessionStore: the client has no replaceIfUnchanged, which recordSecondFactor writes through (UserSessionStoreClient)",
		);
	}
	const k = (sid: string) => `${opts.keyPrefix}${sid}`;
	const logger = opts.logger ?? consoleLogger;

	/**
	 * The envelope in `raw`, or `null` — with one `user_session_corrupt_envelope`
	 * warn — when it does not parse or has the wrong shape. Expiry is the
	 * caller's to judge.
	 */
	const readEnvelope = (sid: string, raw: string): Envelope | null => {
		let parsed: unknown;
		try {
			parsed = JSON.parse(raw);
		} catch (cause) {
			// Object-first, so `sid` and `reason` are structured fields on every
			// `Logger` implementation. The cause is projected: a SyntaxError's
			// message quotes the envelope (the session's claims) around the
			// point the parse failed.
			logger.warn(
				{ sid, reason: "json_parse", err: loggableError(cause) },
				"user_session_corrupt_envelope",
			);
			return null;
		}

		if (!isValidEnvelope(parsed)) {
			logger.warn({ sid, reason: "shape_invalid" }, "user_session_corrupt_envelope");
			return null;
		}
		return parsed;
	};

	return {
		kind: "redis",
		async create(input) {
			const expiresAtMs = input.expiresAt.getTime();
			// An Invalid Date's time is NaN, and `NaN <= 0` is false: without this
			// it would reach Redis as `PX NaN`. A caller fault, not a session.
			if (!Number.isFinite(expiresAtMs)) {
				throw new RangeError(`UserSession ${input.sid}: expiresAt must be a valid date`);
			}
			// The login time: what core's `recordableAuthTime` answers, no later
			// than the host's clock, as the memory store records it. Refused before
			// Redis is asked: `isValidEnvelope` reads back a non-negative timestamp only.
			const authTime = recordableAuthTime(input.sid, input.authTime, Date.now());
			// Likewise how the session was established: only what
			// `SessionAuthentication` admits, `mfaAt` judged on the host's clock
			// (the one a write is checked against) — anything else would be
			// written as an envelope that reads back as corrupt. What core's
			// `recordableSessionAuthentication` answers is what is recorded, never
			// `input.authentication`, as the memory store records it.
			const authentication = recordableSessionAuthentication(
				input.sid,
				input.authentication,
				Date.now(),
			);
			// And the enrollment facts: what core's `recordableEnrollmentFacts`
			// answers, as the memory store records it.
			const enrollmentFacts = recordableEnrollmentFacts(input.sid, input.enrollmentFacts);
			const ttlMs = expiresAtMs - Date.now();
			if (ttlMs <= 0) {
				throw new Error(`UserSession ${input.sid}: expiresAt is in the past`);
			}
			// `authentication` as checked: a copy, its `mfaAt` no later than the
			// host's clock; the facts as checked.
			const envelope = toEnvelope(
				{ ...input, authTime, authentication, enrollmentFacts },
				Date.now(),
			);
			const result = await opts.client.set(
				k(input.sid),
				JSON.stringify(envelope),
				"PX",
				ttlMs,
				"NX",
			);
			if (result === null) {
				throw new Error(`UserSession ${input.sid} already exists`);
			}
		},
		async get(sid) {
			const raw = await opts.client.get(k(sid));
			if (raw === null) return null;
			const stored = readEnvelope(sid, raw);
			if (stored === null || stored.expiresAtMs <= Date.now()) return null;
			return fromEnvelope(stored);
		},
		async recordSecondFactor(sid, event) {
			// A bad event is refused before Redis is asked, gone session or not,
			// its time judged on the host's clock.
			const nowMs = Date.now();
			checkSecondFactorEvent(event, nowMs);
			const nonces = readRenewalNonces(event);
			for (let attempt = 0; attempt < RECORD_SECOND_FACTOR_ATTEMPTS; attempt++) {
				const raw = await opts.client.get(k(sid));
				if (raw === null) return null;
				// Read as `get` reads: a corrupt envelope is a session that is gone.
				const stored = readEnvelope(sid, raw);
				if (stored === null || stored.expiresAtMs <= Date.now()) return null;
				// Judged on the bytes the compare-and-set below writes over: a
				// completion another one overtook finds that one's nonce.
				if (!expectsRenewalNonce(stored.renewalNonce, nonces)) return null;
				const next = sessionAfterSecondFactor(fromEnvelope(stored), event, nowMs);
				if (next === null) return null;
				// The known fields are rewritten; what a newer release added beside
				// them, in the envelope or inside `authentication`, is kept.
				const written: Envelope = {
					...stored,
					amr: [...next.amr],
					authentication: {
						...stored.authentication,
						...toEnvelopeAuthentication(next.authentication),
					},
					// In the same write as the escalation; an event without one keeps it.
					...(nonces.renewalNonce === undefined ? {} : { renewalNonce: nonces.renewalNonce }),
				};
				if (await opts.client.replaceIfUnchanged(k(sid), raw, JSON.stringify(written))) {
					return fromEnvelope(written);
				}
			}
			throw new Error(
				`UserSession ${sid}: recordSecondFactor lost ${RECORD_SECOND_FACTOR_ATTEMPTS} compare-and-sets in a row`,
			);
		},
		async delete(sid) {
			await opts.client.del(k(sid));
		},
	};
}

/**
 * AdapterFactory builder for the Redis-backed `UserSessionStore`, for
 * per-adapter granularity; the bundled `redisSessionStoresModule` covers the
 * common case. The default `keyPrefix` is the bundle's (`ss:us:`), so
 * switching between the two keeps the keyspace. A missing `client` throws at
 * boot, as in `redisChallengeStoreBuilder`, rather than at the first command.
 *
 * The corrupt-envelope warn from `get()` goes to `config.logger`, else the
 * factory context's logger, else `consoleLogger`; a corrupt envelope reads as
 * `null` whichever it is.
 */
export const redisUserSessionStoreBuilder: AdapterBuilder<UserSessionStore> = (config, ctx) => {
	const c = config as { client?: UserSessionStoreClient; keyPrefix?: string; logger?: Logger };
	if (!c.client) {
		throw new Error("redisUserSessionStoreBuilder: 'client' option is required");
	}
	const logger = c.logger ?? ctx?.logger;
	return createRedisUserSessionStore({
		client: c.client,
		keyPrefix: c.keyPrefix ?? "ss:us:",
		...(logger !== undefined ? { logger } : {}),
	});
};
