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
 * The device authorization store's client: semantic operations, each indivisible over a record
 * and its user-code index, whose prefixes hash to one slot.
 */

// --- DeviceCodeStoreClient -------------------------------------------------

/**
 * Where one device authorization lives: `codeKeyPrefix + deviceCode` holds
 * the record, `userKeyPrefix + userCode` holds the device code it belongs to.
 *
 * Every method takes both, because every mutation touches both — `create`
 * writes the pair, `poll` consumes the pair, and `approve`/`deny` reach the
 * record *through* the index. **The two prefixes must hash to the same
 * slot.** A script may only touch keys in the slot it was routed to, and the
 * key it derives from the index is not one the caller could declare up front.
 * `createRedisDeviceCodeStore` guarantees this with one constant `{devauth}`
 * hash tag in both prefixes; a custom keyspace has to guarantee it too.
 */
export interface DeviceCodeKeyspace {
	readonly codeKeyPrefix: string;
	readonly userKeyPrefix: string;
}

/**
 * The record as it lives in Redis: one hash, every field a string. The field
 * names are part of the contract because the scripts read them by name.
 *
 * Numbers are decimal strings and the scope lists are JSON arrays, so a scope
 * value is stored byte-for-byte rather than split on a separator it might
 * contain. Optional fields are *absent* rather than empty: the memory adapter
 * distinguishes "asked for no scope" from "asked for `[]`", and so does this.
 */
export interface DeviceCodeRecordFields {
	readonly userCode: string;
	readonly clientId: string;
	/** Epoch milliseconds. What `poll` measures `expired` against — not the TTL. */
	readonly expiresAtMs: string;
	/** Seconds. Grown in place by `poll` on `slow_down`, so the gate measures against the grown value. */
	readonly intervalSeconds: string;
	readonly status: "pending" | "approved" | "denied";
	/** JSON array. Absent when the device asked for no scope at all. */
	readonly requestedScope?: string;
	/** Set by an approval. */
	readonly subject?: string;
	/** JSON array, set by an approval. */
	readonly grantedScope?: string;
	/** Epoch milliseconds, set by an approval: the `now` the decision was made at. */
	readonly approvedAtMs?: string;
	/** JSON array, set by an approval handed the approving session's `amr`. */
	readonly amr?: string;
	/** Epoch milliseconds, set by an approval handed when the approving session authenticated. */
	readonly authTimeMs?: string;
	/** Epoch milliseconds of the previous poll. Absent until the first. */
	readonly lastPolledAtMs?: string;
}

export interface CreateDeviceCodeRecordInput {
	readonly deviceCode: string;
	readonly userCode: string;
	/**
	 * The deadline both keys expire at, in whole epoch milliseconds within the
	 * Date range. The script writes the pair before its `PEXPIREAT`, so a
	 * deadline Redis refused there would leave both keys with no TTL:
	 * `createRedisDeviceCodeStore` therefore refuses an expiry outside the
	 * Date range before calling `create`, and rounds the one it passes up to a
	 * whole millisecond. A client called some other way must hold to the same.
	 * The record's own `fields.expiresAtMs` stays the exact expiry.
	 */
	readonly expiresAtMs: number;
	readonly fields: DeviceCodeRecordFields;
}

export type DeviceCodeDecisionInput =
	| { readonly decision: "denied" }
	| {
			readonly decision: "approved";
			readonly subject: string;
			/**
			 * Omitted grants `requestedScope` whole. Supplied, it is intersected
			 * with `requestedScope` **inside the operation** — the caller may
			 * narrow, never widen, and reading the record first to intersect
			 * client-side would be the second read the port rules out.
			 */
			readonly grantedScope?: readonly string[];
			/**
			 * The approving session's `amr` and when it authenticated (epoch ms),
			 * each written as handed; omitted, the record holds none. A client
			 * MUST write them in the same atomic write as the approval; one that
			 * does not makes every approval read both as absent.
			 */
			readonly amr?: readonly string[];
			/** See `amr`. */
			readonly authTimeMs?: number;
	  };

export type DeviceCodeDecisionReply =
	| { readonly kind: "ok"; readonly fields: DeviceCodeRecordFields }
	| { readonly kind: "not_found" }
	| { readonly kind: "expired" }
	| { readonly kind: "already_decided"; readonly status: "approved" | "denied" };

export type DeviceCodePollReply =
	| { readonly kind: "not_found" }
	| { readonly kind: "expired" }
	| { readonly kind: "denied" }
	| { readonly kind: "pending" }
	| { readonly kind: "slow_down"; readonly intervalSeconds: number }
	| { readonly kind: "approved"; readonly fields: DeviceCodeRecordFields };

/**
 * Backing client for the `DeviceCodeStore` adapter.
 *
 * Semantic operations rather than a raw `eval`, as {@link RateLimiterClient}
 * and {@link SubjectSessionIndexClient}: `create`, `approve`/`deny` and
 * `poll` must be **indivisible**, and a contract expressed as Redis commands
 * would leave that to the caller's discipline. Lua is the obvious
 * implementation (see `makeIoredisClients`) but not required — anything
 * atomic that reads and writes the pair satisfies this. `poll` matters most:
 * as `HGETALL` then `DEL`, two concurrent polls both observe `approved`, and
 * one human approval becomes two access tokens.
 */
export interface DeviceCodeStoreClient {
	/**
	 * Write the record and the index, both insert-only, both expiring at
	 * `expiresAtMs` — atomically. Resolves `false` when either key already
	 * exists, and writes nothing in that case: a collision is a generator
	 * failure, and overwriting would hand a new device the previous one's
	 * pending approval. `false` is the collision signal the endpoint re-draws
	 * for, so a client that cannot tell which happened — a reply it does not
	 * understand — rejects instead, and the endpoint answers an outage.
	 */
	create(keys: DeviceCodeKeyspace, input: CreateDeviceCodeRecordInput): Promise<boolean>;
	/**
	 * The record behind `userCode`, or `null` when it is absent, past
	 * `expiresAtMs` as of `nowMs`, or already decided. An expired record is
	 * reclaimed on the way, as the memory adapter does.
	 */
	findPending(
		keys: DeviceCodeKeyspace,
		userCode: string,
		nowMs: number,
	): Promise<DeviceCodeRecordFields | null>;
	/**
	 * Move the record behind `userCode` from `pending` to the decision —
	 * atomically with the check that it *is* pending. A second decision must
	 * answer `already_decided` with the first, never overwrite it: a user who
	 * denied a phishing prompt could otherwise be talked into "just trying
	 * again".
	 */
	decide(
		keys: DeviceCodeKeyspace,
		userCode: string,
		nowMs: number,
		input: DeviceCodeDecisionInput,
	): Promise<DeviceCodeDecisionReply>;
	/**
	 * Atomically: enforce the polling interval, read the status, and — when
	 * approved or denied — delete the pair so the answer is given once.
	 *
	 * Required behaviour, in this order:
	 *
	 *   - absent → `not_found`
	 *   - `expiresAtMs <= nowMs` → `expired`, and the pair is deleted. Measured
	 *     against the caller's clock, not the key's TTL: a record still inside
	 *     its TTL must answer `expired` once the timestamp has passed.
	 *   - polled within `intervalSeconds` of the previous poll → `slow_down`,
	 *     with `intervalSeconds` grown by `slowDownIncrementSeconds` **and
	 *     written back**, so the next gate measures against the grown value
	 *     (RFC 8628 §3.5: "increased by 5 seconds for this and all subsequent
	 *     requests"). The gate runs before the status read, so an over-eager
	 *     poller is not rewarded with `approved`.
	 *   - `denied` → `denied`, and the pair is deleted
	 *   - `pending` → `pending`
	 *   - `approved` → `approved` with the record, and the pair is deleted
	 */
	poll(
		keys: DeviceCodeKeyspace,
		deviceCode: string,
		nowMs: number,
		slowDownIncrementSeconds: number,
	): Promise<DeviceCodePollReply>;
	/** Delete the record and its index together. Absence is not an error. */
	remove(keys: DeviceCodeKeyspace, deviceCode: string): Promise<void>;
}
