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
	consoleLogger,
	type Logger,
	loggableError,
	type RegisteredRP,
	type SessionRPRegistry,
} from "@o3co/auth-provider-core";
import type { SessionRPRegistryClient } from "./clients.mjs";
import { createRedisSidHash } from "./internal/redisSidHash.mjs";

export interface RedisSessionRPRegistryOptions {
	readonly client: SessionRPRegistryClient;
	readonly keyPrefix: string;
	/**
	 * Where `listRPs()` reports a stored record it cannot read: one
	 * `session_rp_registry_corrupt_envelope` warn, `reason` `json_parse` (with
	 * the parser's projection as `err`) or `shape_invalid`.
	 * `redisSessionStoresModule` passes the composition's `logger` slot;
	 * absent, `consoleLogger`.
	 */
	readonly logger?: Logger;
}

/**
 * The JSON stored as one HASH field value: a `RegisteredRP` with
 * `registeredAt` as epoch milliseconds, which is loss-free where a date string
 * can drift in timezone or precision.
 *
 * Derived from `RegisteredRP`, so every key the record requires the envelope
 * requires too: a write that forgot a logout field fails to compile rather
 * than dropping the RP from the logout cascade, and a field added to the
 * record cannot be left out of what the store writes. An unset logout field is
 * `undefined`, left out by `JSON.stringify` and read back as `undefined`,
 * never `""` or `null`. `isValidRPEnvelope` checks every field's type,
 * present or not.
 */
type RPEnvelope = Omit<RegisteredRP, "registeredAt"> & { readonly registeredAtMs: number };

function serialize(rp: RegisteredRP): string {
	// A literal naming every field, so forgetting one is a compile error (see
	// `RPEnvelope`). Nothing is coerced to `""` or `false` on the way through.
	const env: RPEnvelope = {
		clientId: rp.clientId,
		registeredAtMs: rp.registeredAt.getTime(),
		backchannelLogoutUri: rp.backchannelLogoutUri,
		backchannelLogoutSessionRequired: rp.backchannelLogoutSessionRequired,
		frontchannelLogoutUri: rp.frontchannelLogoutUri,
		frontchannelLogoutSessionRequired: rp.frontchannelLogoutSessionRequired,
	};
	return JSON.stringify(env);
}

function isRecord(value: unknown): value is Record<string, unknown> {
	// Arrays are refused here, as the userSessionStore envelope guard does, so
	// a payload like `["client-1", ...]` fails the shape check at this layer
	// rather than by accident in `isValidRPEnvelope`.
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

const isOptional = (value: unknown, type: "string" | "boolean"): boolean =>
	value === undefined || typeof value === type;

/**
 * Every field, including the four logout ones: a stored record is data this
 * store did not necessarily write. `backchannelLogoutSessionRequired:
 * "false"` would otherwise come back typed as a boolean and read as truthy —
 * `sid` sent to an RP that asked not to receive it — so a field of the wrong
 * type makes the whole record corrupt, as a bad `clientId` already does.
 */
function isValidRPEnvelope(env: unknown): env is RPEnvelope {
	if (!isRecord(env)) return false;
	return (
		typeof env.clientId === "string" &&
		typeof env.registeredAtMs === "number" &&
		Number.isFinite(env.registeredAtMs) &&
		isOptional(env.backchannelLogoutUri, "string") &&
		isOptional(env.backchannelLogoutSessionRequired, "boolean") &&
		isOptional(env.frontchannelLogoutUri, "string") &&
		isOptional(env.frontchannelLogoutSessionRequired, "boolean")
	);
}

function deserialize(json: string, sid: string, logger: Logger): RegisteredRP | null {
	// The userSessionStore corrupt-envelope warn shape: object-first
	// `{ sid, reason, err? }`. The parse error is `err` as core's
	// `loggableError` projects it, because a SyntaxError's message quotes the
	// stored value around the point the parse failed. No part of the stored
	// value is logged: a corrupt value may contain credentials.
	let parsed: unknown;
	try {
		parsed = JSON.parse(json);
	} catch (cause) {
		logger.warn(
			{ sid, reason: "json_parse", err: loggableError(cause) },
			"session_rp_registry_corrupt_envelope",
		);
		return null;
	}
	if (!isValidRPEnvelope(parsed)) {
		logger.warn({ sid, reason: "shape_invalid" }, "session_rp_registry_corrupt_envelope");
		return null;
	}
	const env = parsed;
	return {
		clientId: env.clientId,
		registeredAt: new Date(env.registeredAtMs),
		// Absent keys are `undefined` — do not fallback to false/null/empty.
		backchannelLogoutUri: env.backchannelLogoutUri,
		backchannelLogoutSessionRequired: env.backchannelLogoutSessionRequired,
		frontchannelLogoutUri: env.frontchannelLogoutUri,
		frontchannelLogoutSessionRequired: env.frontchannelLogoutSessionRequired,
	};
}

/**
 * Redis-backed SessionRPRegistry: one HASH per sid at `${keyPrefix}${sid}`,
 * each field a `clientId` holding its JSON `RPEnvelope`. Writing the same
 * `clientId` replaces the earlier value, which meets the "same clientId
 * upserts" contract with no CAS loop. The HASH layout and its TTL
 * (`session.expiresAt`, set in the same pipeline as the `HSET`) are
 * `createRedisSidHash`'s.
 */
export function createRedisSessionRPRegistry(
	opts: RedisSessionRPRegistryOptions,
): SessionRPRegistry {
	const hash = createRedisSidHash({ client: opts.client, keyPrefix: opts.keyPrefix });
	const logger = opts.logger ?? consoleLogger;
	return {
		kind: "redis",
		async registerRP(sid, rp, expiresAt) {
			// NaN serialises as JSON `null`, which the reader refuses — the RP
			// would be written and then skipped by every logout fan-out.
			if (!Number.isFinite(rp.registeredAt.getTime())) {
				throw new RangeError("SessionRPRegistry.registerRP: registeredAt must be a valid date");
			}
			await hash.setField(sid, rp.clientId, serialize(rp), expiresAt);
		},
		async listRPs(sid) {
			const values = await hash.listValues(sid);
			return values
				.map((value) => deserialize(value, sid, logger))
				.filter((rp): rp is RegisteredRP => rp !== null);
		},
		async removeBySid(sid) {
			await hash.removeBySid(sid);
		},
	};
}

/**
 * AdapterFactory builder for the Redis-backed `SessionRPRegistry`, for
 * per-adapter granularity; the bundled `redisSessionStoresModule` covers the
 * common case. The default `keyPrefix` is the bundle's (`ss:rp:`), so
 * switching between the two keeps the keyspace. A missing `client` throws at
 * boot, as in `redisChallengeStoreBuilder`, rather than at the first command.
 *
 * The corrupt-envelope warn from `listRPs()` goes to `config.logger`, else the
 * factory context's logger, else `consoleLogger`; corrupt entries are dropped
 * from the result whichever it is.
 */
export const redisSessionRPRegistryBuilder: AdapterBuilder<SessionRPRegistry> = (config, ctx) => {
	const c = config as {
		client?: SessionRPRegistryClient;
		keyPrefix?: string;
		logger?: Logger;
	};
	if (!c.client) {
		throw new Error("redisSessionRPRegistryBuilder: 'client' option is required");
	}
	const logger = c.logger ?? ctx?.logger;
	return createRedisSessionRPRegistry({
		client: c.client,
		keyPrefix: c.keyPrefix ?? "ss:rp:",
		...(logger !== undefined ? { logger } : {}),
	});
};
