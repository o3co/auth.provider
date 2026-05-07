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
	AdapterBuilder,
	CreateUserSessionInput,
	Logger,
	UserSession,
	UserSessionClaims,
	UserSessionStore,
} from "@o3co/auth-provider-core";
import type { UserSessionStoreClient } from "./clients.mjs";

export interface RedisUserSessionStoreOptions {
	readonly client: UserSessionStoreClient;
	readonly keyPrefix: string;
	/**
	 * Optional structured logger consumed by `get()` when a stored
	 * envelope fails JSON.parse or shape validation (TS-3). Optional
	 * chaining is used so callers that don't inject a logger get the
	 * same fail-closed `null` return without an emitted warn. Phase F
	 * will add a `consoleLogger` fallback once the D-4 ComponentMap
	 * `logger` slot lands and module wiring threads it through.
	 */
	readonly logger?: Logger;
}

interface Envelope {
	sid: string;
	sub: string;
	authTimeMs: number;
	createdAtMs: number;
	expiresAtMs: number;
	claims: Record<string, unknown>;
}

/**
 * Maximum representable date in milliseconds (`new Date(8_640_000_000_000_000)`
 * is the upper bound of valid JavaScript Date values per ECMA-262 §21.4.1.1).
 * Values outside `[0, MAX_DATE_MS]` cannot survive a `new Date(ms)` round-trip
 * — they produce `Invalid Date` whose `getTime()` returns `NaN`.
 */
const MAX_DATE_MS = 8_640_000_000_000_000;

/**
 * Per-field timestamp predicate: must be a non-negative safe integer within
 * the `Date` valid range. Using `Number.isSafeInteger` (vs the looser
 * `Number.isFinite`) closes a stricter form of the TS-3 expiry-bypass:
 * very large finite numbers (e.g. `Number.MAX_VALUE` or any value > 2^53)
 * lose precision and may produce `Invalid Date` via `new Date(ms)`. The
 * comparison `expiresAtMs <= Date.now()` could then evaluate to `false`
 * against an effectively-never-expiring envelope, again silently bypassing
 * the gate. Per Copilot review on PR #123.
 *
 * Negative values are rejected because session timestamps are always
 * positive epoch milliseconds; a negative value would map to a pre-1970
 * Date, which is structurally meaningless for OAuth session lifecycle.
 */
const isValidTimestamp = (x: unknown): x is number =>
	typeof x === "number" && Number.isSafeInteger(x) && x >= 0 && x <= MAX_DATE_MS;

/**
 * Hand-rolled type predicate for `Envelope`. Lighter than Zod for the
 * storage layer and matches the Wave 5g `ts-safety-batch` convention.
 *
 * Timestamp validation uses `isValidTimestamp` (safe integer + Date-range
 * bounded). The original `expiresAtMs <= Date.now()` comparison silently
 * returned `false` for `undefined`/`NaN`, bypassing the expiry filter and
 * propagating `Invalid Date` into the returned `UserSession`.
 *
 * `claims` must be a plain object — `[]` and `null` both fail the
 * `typeof === "object"` plus index-signature contract. Callers that need
 * to support `claims: null` should change the predicate explicitly; the
 * fail-closed default is the safer posture for a security-critical path.
 *
 * Per TS-3 (Wave 5j) + Copilot review on PR #123 (timestamp tightening).
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
		!Array.isArray(e.claims)
	);
};

const toEnvelope = (input: CreateUserSessionInput, createdAtMs: number): Envelope => ({
	sid: input.sid,
	sub: input.sub,
	authTimeMs: input.authTime.getTime(),
	createdAtMs,
	expiresAtMs: input.expiresAt.getTime(),
	claims: { ...input.claims },
});

const fromEnvelope = (e: Envelope): UserSession => ({
	sid: e.sid,
	sub: e.sub,
	authTime: new Date(e.authTimeMs),
	createdAt: new Date(e.createdAtMs),
	expiresAt: new Date(e.expiresAtMs),
	claims: { ...e.claims } as UserSessionClaims,
});

/**
 * Redis-backed UserSessionStore. Per A4 §5.1 + §7.2.
 *
 * Storage shape: each session is a single Redis string key
 * `${keyPrefix}${sid}` whose value is a JSON-encoded envelope, with TTL
 * applied via SET PX. The v0.4.x lost-update window is **structurally
 * absent**: this adapter exposes only `create` (atomic SET NX),
 * `get`, `delete`. No GET → mutate → SET path exists at the v0.5.0
 * `UserSessionStore` interface level; claims update is deferred post-publish.
 *
 * Atomicity:
 *  - `create` uses SET NX PX — atomic insert-only, same primitive as A1
 *    ChallengeStore.issue and A3 registerFamily.
 *  - `get` is a read-only GET (no PTTL round-trip needed; expiresAtMs is
 *    embedded in the JSON envelope and the SET PX TTL eventually deletes
 *    the key).
 *  - `delete` is single-key DEL.
 */
export function createRedisUserSessionStore(opts: RedisUserSessionStoreOptions): UserSessionStore {
	const k = (sid: string) => `${opts.keyPrefix}${sid}`;
	return {
		kind: "redis",
		async create(input) {
			const ttlMs = input.expiresAt.getTime() - Date.now();
			if (ttlMs <= 0) {
				throw new Error(`UserSession ${input.sid}: expiresAt is in the past`);
			}
			const envelope = toEnvelope(input, Date.now());
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

			// TS-3 (Wave 5j): the previous `JSON.parse(raw) as Envelope` was a
			// compile-time cast only. A corrupt envelope with `expiresAtMs:
			// undefined` made `expiresAtMs <= Date.now()` evaluate to `false`
			// (NaN comparison), bypassing the expiry filter and returning a
			// session with `Invalid Date` fields. Treat any parse / shape
			// failure as fail-closed (return null) and emit a structured
			// warn for operator observability.
			let parsed: unknown;
			try {
				parsed = JSON.parse(raw);
			} catch (cause) {
				// Object-first call shape per the D-4 Logger interface — keeps
				// `sid` / `reason` reliably emitted as structured fields across
				// `Logger` implementations (pino, console, custom). Per Copilot
				// review on PR #123.
				opts.logger?.warn(
					{ sid, reason: "json_parse", cause },
					"user_session_corrupt_envelope: JSON.parse failed",
				);
				return null;
			}

			if (!isValidEnvelope(parsed)) {
				opts.logger?.warn(
					{ sid, reason: "shape_invalid" },
					"user_session_corrupt_envelope: shape invalid",
				);
				return null;
			}

			if (parsed.expiresAtMs <= Date.now()) return null;
			return fromEnvelope(parsed);
		},
		async delete(sid) {
			await opts.client.del(k(sid));
		},
	};
}

/**
 * AdapterFactory builder for the Redis-backed `UserSessionStore` (AS-9).
 *
 * Use when per-adapter `AdapterFactory` granularity is needed; for the common
 * case the bundled `redisSessionStoresModule` is sufficient. Default
 * `keyPrefix` matches the bundle's production layout (`ss:us:`) so swapping
 * between bundle and individual builder does not change the keyspace.
 *
 * Mirrors the boot-time guard pattern of `redisChallengeStoreBuilder`
 * (TS-M2): missing `client` throws at boot rather than crashing at first
 * Redis op. Optional `logger` is passed through for the TS-3 corrupt-envelope
 * warn path; absent logger fails closed silently per existing convention.
 */
export const redisUserSessionStoreBuilder: AdapterBuilder<UserSessionStore> = (config, _ctx) => {
	const c = config as { client?: UserSessionStoreClient; keyPrefix?: string; logger?: Logger };
	if (!c.client) {
		throw new Error("redisUserSessionStoreBuilder: 'client' option is required");
	}
	return createRedisUserSessionStore({
		client: c.client,
		keyPrefix: c.keyPrefix ?? "ss:us:",
		...(c.logger !== undefined ? { logger: c.logger } : {}),
	});
};
