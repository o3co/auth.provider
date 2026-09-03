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
 * Redis-backed `DeviceCodeStore` (#433) — what lets the device grant run
 * under `deployment.mode = "multi"`.
 *
 * The in-memory store is refused there, correctly: pending authorizations
 * fork per replica, so the human approves a code on the replica that served
 * the verification page while the device polls one that has never heard of
 * it and is told the code does not exist. This adapter puts the record where
 * every replica reads it, and keeps the port's atomicity by making each
 * operation one Lua script — see `DeviceCodeStoreClient` for what each must
 * guarantee and `makeIoredisClients` for the scripts.
 *
 * ### Two keys, one slot
 *
 *     <keyPrefix>{devauth}:code:<device_code>   HASH    the record
 *     <keyPrefix>{devauth}:user:<user_code>     STRING  the device code
 *
 * The record is keyed by the device code and `approve`/`deny` arrive with the
 * user code, so there is an index — and a script that follows the index to
 * the record touches two keys derived from two independent random values.
 * Redis Cluster runs a script in one slot, so the pair has to hash together.
 * The constant `{devauth}` hash tag does that, at the cost of concentrating
 * every device authorization on one slot. For this flow's volume — a
 * human-initiated ceremony, not per-request traffic — that is an acceptable
 * trade, but it is a real one, which is why it is written here rather than
 * discovered later. The alternative, storing the record twice under each key,
 * would make `approve` and `poll` non-atomic across the pair: precisely what
 * the port forbids.
 *
 * ### TTL versus `expiresAtMs`
 *
 * Both keys carry the authorization's own expiry as an absolute deadline, so
 * expired records are reclaimed by Redis rather than swept. But the port's
 * contract is the timestamp, not the TTL: `poll` answers `expired` for a
 * record still inside its TTL whose `expiresAtMs` has passed on the caller's
 * clock, and drops it — the conformance suite checks that boundary. The TTL
 * is the safety net for a record nobody asks about again, not the source of
 * truth.
 *
 * ### The record
 *
 * One hash per authorization, every field a string; the scope lists are JSON
 * arrays so a scope value is stored byte-for-byte. A hash rather than a JSON
 * document so the scripts mutate fields in place — `status`, the grown
 * `intervalSeconds`, `lastPolledAtMs` — without re-encoding the whole thing,
 * and without `cjson`'s habit of turning an empty array into an object on
 * the way back out.
 */

import {
	type AdapterBuilder,
	type ApproveDeviceAuthorizationInput,
	type CreateDeviceAuthorizationInput,
	type DeviceAuthorization,
	type DeviceCodeStore,
	type DeviceDecisionOutcome,
	type DevicePollOutcome,
	defineModule,
} from "@o3co/auth-provider-core";
import { z } from "zod";
import type {
	DeviceCodeDecisionReply,
	DeviceCodeKeyspace,
	DeviceCodeRecordFields,
	DeviceCodeStoreClient,
} from "./clients.mjs";

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
 * How much a too-fast poll adds to the interval.
 *
 * RFC 8628 §3.5 defines `slow_down` as "the interval MUST be increased by 5
 * seconds for this and all subsequent requests". The same value the memory
 * adapter uses, and the store enforces the increased interval, not just
 * reports it — a server that says `slow_down` while measuring against the
 * original interval is asking for a change it does not itself observe.
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

/**
 * The memory adapter's `toAuthorization`, from hash fields: optional fields
 * absent in the record stay absent in the result rather than becoming
 * `undefined` properties.
 */
const toAuthorization = (fields: DeviceCodeRecordFields): DeviceAuthorization => {
	const requestedScope = parseScope(fields.requestedScope);
	const grantedScope = parseScope(fields.grantedScope);
	return {
		userCode: fields.userCode,
		clientId: fields.clientId,
		...(requestedScope ? { requestedScope } : {}),
		expiresAtMs: Number(fields.expiresAtMs),
		intervalSeconds: Number(fields.intervalSeconds),
		status: fields.status,
		...(fields.subject === undefined ? {} : { subject: fields.subject }),
		...(grantedScope ? { grantedScope } : {}),
	};
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
			const fields: DeviceCodeRecordFields = {
				userCode: input.userCode,
				clientId: input.clientId,
				expiresAtMs: String(input.expiresAtMs),
				intervalSeconds: String(input.intervalSeconds),
				status: "pending",
				...(input.requestedScope ? { requestedScope: JSON.stringify(input.requestedScope) } : {}),
			};
			const created = await client.create(keys, {
				deviceCode: input.deviceCode,
				userCode: input.userCode,
				expiresAtMs: input.expiresAtMs,
				fields,
			});
			// A collision here is a generator failure, not traffic. The script
			// wrote nothing, so the device that holds the existing code keeps
			// the approval its user is about to give.
			if (!created) throw new Error("device authorization code collision");
		},

		async findPendingByUserCode(userCode, nowMs) {
			const fields = await client.findPending(keys, userCode, nowMs);
			return fields === null ? null : toAuthorization(fields);
		},

		async approve(input: ApproveDeviceAuthorizationInput): Promise<DeviceDecisionOutcome> {
			// Omitted means "grant what was asked for"; supplied is narrowed
			// against `requestedScope` inside the script, never widened.
			return decisionOutcome(
				await client.decide(keys, input.userCode, input.nowMs, {
					decision: "approved",
					subject: input.subject,
					...(input.grantedScope === undefined ? {} : { grantedScope: input.grantedScope }),
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

/**
 * AdapterFactory builder for runtime-config-driven backend selection
 * (composition pattern §8.4). Consumer registers via:
 *   factory.register("redis", redisDeviceCodeStoreBuilder);
 * Then calls:
 *   factory.create({ type: "redis", client, keyPrefix: "devauth:" });
 */
export const redisDeviceCodeStoreBuilder: AdapterBuilder<DeviceCodeStore> = (config, _ctx) => {
	const c = config as { client?: DeviceCodeStoreClient; keyPrefix?: string };
	// Same structural guard as `redisChallengeStoreBuilder`: fail at boot
	// rather than at the first device poll with a cryptic `Cannot read
	// properties of undefined`.
	if (!c.client) {
		throw new Error("redisDeviceCodeStoreBuilder: 'client' option is required");
	}
	return createRedisDeviceCodeStore({
		client: c.client,
		keyPrefix: c.keyPrefix ?? "devauth:",
	});
};

/**
 * `defineModule` manifest for the Redis DeviceCodeStore. Static composition
 * path (§8.1). For runtime-config-driven selection use the builder above.
 *
 * Not in `REPLICA_UNSAFE_MODULE_REASONS`, which is the point: a composition
 * that mounts `deviceGrantModule` with this store may declare
 * `deployment.mode = "multi"`. The `deviceCodeStoreClient` slot it requires
 * comes from `makeIoredisClients` (or the standalone's shared clients module).
 *
 * configSchema: top-level key `redisDeviceCodeStore` (module-namespaced per
 * master roadmap §3.5 — NO bare `keyPrefix` top-level key).
 */
export const redisDeviceCodeStoreModule = defineModule({
	name: "redis-device-code-store",
	requires: ["deviceCodeStoreClient", "config"] as const,
	configSchema: z.object({
		redisDeviceCodeStore: z
			.object({
				keyPrefix: z.string().default("devauth:"),
			})
			.default({ keyPrefix: "devauth:" }),
	}),
	provides: {
		deviceCodeStore: (deps) => {
			const cfg = (deps.config as unknown as { redisDeviceCodeStore: { keyPrefix: string } })
				.redisDeviceCodeStore;
			return createRedisDeviceCodeStore({
				client: deps.deviceCodeStoreClient,
				keyPrefix: cfg.keyPrefix,
			});
		},
	},
});
