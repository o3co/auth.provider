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
 * Redis-backed `DeviceCodeStore`, so the device grant can run under
 * `core.deployment.mode = "multi"`: the user approves on one replica while the device
 * polls another. Each operation is one Lua script (`makeIoredisClients`), which
 * keeps the port's atomicity; `DeviceCodeStoreClient` states what each must
 * guarantee.
 *
 *     <keyPrefix>{devauth}:code:<device_code>   HASH    the record
 *     <keyPrefix>{devauth}:user:<user_code>     STRING  the device code
 *
 * `approve`/`deny` arrive with the user code and follow the index to the record
 * in one script, and Redis Cluster runs a script in one slot, so the constant
 * `{devauth}` tag puts every device authorization on one slot: a real
 * concentration, acceptable for a human-paced ceremony. Writing the record under
 * both keys instead would make `approve` and `poll` non-atomic across the pair.
 *
 * Expiry is `expiresAtMs` on the caller's clock: `poll` answers `expired` even
 * inside the TTL. The keys' `PEXPIREAT` deadline, the expiry rounded up to a
 * whole millisecond, only reclaims records nobody asks about again.
 *
 * The record is a hash of strings, so the scripts update `status`,
 * `intervalSeconds` and `lastPolledAtMs` in place without a `cjson` round-trip
 * (which turns an empty array into an object); scope lists are JSON arrays.
 */

import {
	type AdapterBuilder,
	type ApproveDeviceAuthorizationInput,
	authTimeClaim,
	type CreateDeviceAuthorizationInput,
	type DeviceAuthorization,
	type DeviceCodeStore,
	DeviceCodeStoreError,
	type DeviceDecisionOutcome,
	type DevicePollOutcome,
	defineModule,
	isStorableExpiry,
	wellFormedAmr,
} from "@o3co/auth-provider-core";
import type {
	DeviceCodeDecisionReply,
	DeviceCodeKeyspace,
	DeviceCodeRecordFields,
	DeviceCodeStoreClient,
} from "./clients.mjs";
import { keyPrefixSection, redisReference } from "./internal/section.mjs";

/**
 * Options for createRedisDeviceCodeStore.
 */
export interface RedisDeviceCodeStoreOptions {
	readonly client: DeviceCodeStoreClient;
	/** Outer namespace; the `{devauth}` hash tag and the `code:`/`user:` segments follow it. */
	readonly keyPrefix: string;
}

/**
 * The one hash tag every device authorization shares. Constant on purpose:
 * it is what puts the record and the index in one slot (see the file header).
 */
const DEVICE_CODE_HASH_TAG = "{devauth}";

/**
 * How much a too-fast poll adds to the interval. RFC 8628 §3.5: on `slow_down`
 * "the interval MUST be increased by 5 seconds for this and all subsequent
 * requests". The store enforces the increased interval, not only reports it.
 */
const SLOW_DOWN_INCREMENT_SECONDS = 5;

const parseScope = (json: string | undefined): readonly string[] | undefined => {
	if (json === undefined) return undefined;
	// The scripts only ever write what `JSON.stringify` of a string array
	// produced; anything else is external mutation and reads as no scope,
	// which is the fail-closed direction for a grant.
	try {
		const parsed: unknown = JSON.parse(json);
		return Array.isArray(parsed) ? parsed.filter((s): s is string => typeof s === "string") : [];
	} catch {
		return [];
	}
};

/** An epoch-ms field as the scripts write it, or `undefined` when there is none to read. */
const parseInstant = (value: string | undefined): number | undefined => {
	if (value === undefined) return undefined;
	const ms = Number(value);
	return Number.isFinite(ms) ? ms : undefined;
};

/**
 * A stored authentication instant, or `undefined` when there is none to read.
 * Only an approval writes it, as the whole epoch milliseconds of a `Date`
 * `approve` accepts; any other spelling (empty, signed, fractional, exponent
 * form, past the Date range) reads as absent rather than as an instant.
 */
const parseAuthTimeMs = (value: string | undefined): number | undefined => {
	if (value === undefined || !/^(?:0|[1-9][0-9]*)$/.test(value)) return undefined;
	const ms = Number(value);
	return authTimeClaim(new Date(ms)) === undefined ? undefined : ms;
};

/**
 * A stored `amr`, or `undefined` when there is none to read. Only an approval
 * writes it, and only as a well-formed list; any other value was written
 * around the store and reads as absent, which the grant reads as "cannot tell".
 */
const parseAmr = (json: string | undefined): readonly string[] | undefined => {
	if (json === undefined) return undefined;
	try {
		return wellFormedAmr(JSON.parse(json));
	} catch {
		return undefined;
	}
};

/**
 * The authorization the hash fields hold; a field the hash lacks is
 * `undefined`. Every field is named, so one this copy forgets is a compile
 * error rather than a silent drop.
 */
const toAuthorization = (fields: DeviceCodeRecordFields): DeviceAuthorization => ({
	userCode: fields.userCode,
	clientId: fields.clientId,
	requestedScope: parseScope(fields.requestedScope),
	expiresAtMs: Number(fields.expiresAtMs),
	intervalSeconds: Number(fields.intervalSeconds),
	status: fields.status,
	subject: fields.subject,
	grantedScope: parseScope(fields.grantedScope),
	// Absent before an approval and on older records; a non-finite value reads
	// as absent too, which a poll under a sessions boundary refuses.
	approvedAtMs: parseInstant(fields.approvedAtMs),
	// Absent unless an approval was handed them, and on records an older
	// release approved.
	amr: parseAmr(fields.amr),
	authTimeMs: parseAuthTimeMs(fields.authTimeMs),
});

/**
 * An approval's `amr` as the script is handed it. Absent stays absent.
 *
 * @throws `RangeError` for one that is not a non-empty list of non-empty strings.
 */
const approvedAmr = (amr: readonly string[] | undefined): readonly string[] | undefined => {
	if (amr === undefined) return undefined;
	const copy = wellFormedAmr(amr);
	if (copy === undefined) {
		throw new RangeError(
			"DeviceCodeStore.approve: amr must be a non-empty list of non-empty strings",
		);
	}
	return copy;
};

/**
 * An approval's authentication instant as the script is handed it, in epoch
 * milliseconds. Absent stays absent.
 *
 * @throws `RangeError` for one that is not a valid `Date` at or after the epoch.
 */
const approvedAuthTimeMs = (authTime: Date | undefined): number | undefined => {
	if (authTime === undefined) return undefined;
	if (!(authTime instanceof Date && authTimeClaim(authTime) !== undefined)) {
		throw new RangeError(
			"DeviceCodeStore.approve: authTime must be a valid Date at or after the epoch",
		);
	}
	return authTime.getTime();
};

const decisionOutcome = (reply: DeviceCodeDecisionReply): DeviceDecisionOutcome => {
	switch (reply.kind) {
		case "ok":
			return { status: "ok", authorization: toAuthorization(reply.fields) };
		case "already_decided":
			return { status: "already_decided", current: reply.status };
		case "expired":
			return { status: "expired" };
		case "not_found":
			return { status: "not_found" };
	}
};

export function createRedisDeviceCodeStore(opts: RedisDeviceCodeStoreOptions): DeviceCodeStore {
	const { client, keyPrefix } = opts;
	const keys: DeviceCodeKeyspace = {
		codeKeyPrefix: `${keyPrefix}${DEVICE_CODE_HASH_TAG}:code:`,
		userKeyPrefix: `${keyPrefix}${DEVICE_CODE_HASH_TAG}:user:`,
	};

	return {
		kind: "redis",

		async create(input: CreateDeviceAuthorizationInput) {
			// NaN is never `<= now`, and `PEXPIREAT NaN` fails after the pair is
			// written, so such a record would read as pending forever.
			if (!isStorableExpiry(input.expiresAtMs)) {
				throw new RangeError(
					`DeviceCodeStore.create: expiresAtMs must be a finite instant within the Date range (got ${String(input.expiresAtMs)})`,
				);
			}
			const fields: DeviceCodeRecordFields = {
				userCode: input.userCode,
				clientId: input.clientId,
				expiresAtMs: String(input.expiresAtMs),
				intervalSeconds: String(input.intervalSeconds),
				status: "pending",
				// Left out rather than `undefined`: a hash cannot hold `undefined`,
				// and a third-party client may write every key it is handed (the
				// conformance suite, not the compiler, holds this write). Truthiness,
				// not `=== undefined`: an untyped caller's `null`, `""` or `false`
				// stays "no scope" instead of being stored and failing `approve`. An
				// array, empty included, is kept.
				...(input.requestedScope ? { requestedScope: JSON.stringify(input.requestedScope) } : {}),
			};
			const created = await client.create(keys, {
				deviceCode: input.deviceCode,
				userCode: input.userCode,
				// Rounded up, so the keys outlive the record's own expiry rather
				// than die a fraction of a millisecond before it.
				expiresAtMs: Math.ceil(input.expiresAtMs),
				fields,
			});
			// A collision here is a generator failure, not traffic. The script
			// wrote nothing, so the device that holds the existing code keeps
			// the approval its user is about to give.
			if (!created) {
				throw new DeviceCodeStoreError({
					reason: "collision",
					message: "device authorization code collision",
				});
			}
		},

		async findPendingByUserCode(userCode, nowMs) {
			const fields = await client.findPending(keys, userCode, nowMs);
			return fields === null ? null : toAuthorization(fields);
		},

		async approve(input: ApproveDeviceAuthorizationInput): Promise<DeviceDecisionOutcome> {
			// Refused before the script runs, so a refused approval writes nothing.
			const amr = approvedAmr(input.amr);
			const authTimeMs = approvedAuthTimeMs(input.authTime);
			// Omitted means "grant what was asked for"; supplied is narrowed
			// against `requestedScope` inside the script, never widened.
			return decisionOutcome(
				await client.decide(keys, input.userCode, input.nowMs, {
					decision: "approved",
					subject: input.subject,
					...(input.grantedScope === undefined ? {} : { grantedScope: input.grantedScope }),
					...(amr === undefined ? {} : { amr }),
					...(authTimeMs === undefined ? {} : { authTimeMs }),
				}),
			);
		},

		async deny(userCode, nowMs): Promise<DeviceDecisionOutcome> {
			return decisionOutcome(await client.decide(keys, userCode, nowMs, { decision: "denied" }));
		},

		async poll(deviceCode, nowMs): Promise<DevicePollOutcome> {
			const reply = await client.poll(keys, deviceCode, nowMs, SLOW_DOWN_INCREMENT_SECONDS);
			switch (reply.kind) {
				case "approved":
					return { status: "approved", authorization: toAuthorization(reply.fields) };
				case "slow_down":
					return { status: "slow_down", intervalSeconds: reply.intervalSeconds };
				default:
					return { status: reply.kind };
			}
		},

		async remove(deviceCode) {
			await client.remove(keys, deviceCode);
		},
	};
}

/** AdapterFactory builder for runtime-config-driven backend selection. */
export const redisDeviceCodeStoreBuilder: AdapterBuilder<DeviceCodeStore> = (config, _ctx) => {
	const c = config as { client?: DeviceCodeStoreClient; keyPrefix?: string };
	// Fail at boot rather than with a cryptic `TypeError` at the first device poll.
	if (!c.client) {
		throw new Error("redisDeviceCodeStoreBuilder: 'client' option is required");
	}
	return createRedisDeviceCodeStore({
		client: c.client,
		keyPrefix: c.keyPrefix ?? "devauth:",
	});
};

/**
 * `defineModule` manifest for the Redis DeviceCodeStore (static composition;
 * the builder above is for runtime selection). Declares no `replicaSafety`, so
 * a composition mounting `deviceGrantModule` with it may declare
 * `core.deployment.mode = "multi"`. The `deviceCodeStoreClient` slot comes from
 * `makeIoredisClients` (or the standalone's shared clients module); its
 * section, `redis-device-code-store`, holds `keyPrefix` (strict).
 */
export const redisDeviceCodeStoreModule = defineModule({
	name: "redis-device-code-store",
	requires: ["deviceCodeStoreClient"] as const,
	section: {
		schema: keyPrefixSection("devauth:"),
		reference: redisReference(),
		relocatedFrom: { redisDeviceCodeStore: { to: "", environmentVariable: null } },
	},
	provides: {
		deviceCodeStore: ({ section, deviceCodeStoreClient }) =>
			createRedisDeviceCodeStore({
				client: deviceCodeStoreClient,
				keyPrefix: section.keyPrefix,
			}),
	},
});
