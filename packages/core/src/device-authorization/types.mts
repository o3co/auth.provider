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
 * The `DeviceCodeStore` port — server state for the OAuth 2.0 Device
 * Authorization Grant (RFC 8628).
 *
 * A device asks for a code, a human approves it elsewhere, and the device
 * polls; these requests race. So `approve`, `deny` and `poll` are **atomic
 * operations, not read-then-write pairs**: a `find` + `update` `poll` lets
 * two concurrent polls both see `approved` and mint two access tokens from
 * one approval.
 */

import type { AbsencePolicy } from "../modules/manifest/absence-policy.mjs";

/**
 * What the authorization server knows about one device authorization.
 *
 * `deviceCode` is deliberately absent: it is the device's bearer credential,
 * a lookup key rather than a field to hand back.
 *
 * Every field is a required key, `undefined` where there is none: stores
 * rebuild the record field by field, and a required key turns a forgotten
 * field (a lost `subject` or `grantedScope`) into a compile error.
 */
export interface DeviceAuthorization {
	/** The code the human types. Normalised — see `normaliseUserCode`. */
	readonly userCode: string;
	readonly clientId: string;
	/** Scope the device asked for, before any policy narrowing; `undefined` when it asked for none. */
	readonly requestedScope: readonly string[] | undefined;
	readonly expiresAtMs: number;
	/** Minimum seconds between polls, as advertised to the device. */
	readonly intervalSeconds: number;
	readonly status: DeviceAuthorizationStatus;
	/** Set when `status === "approved"`: who approved it. `undefined` before. */
	readonly subject: string | undefined;
	/** Set when `status === "approved"`: what they approved. `undefined` before. */
	readonly grantedScope: readonly string[] | undefined;
	/**
	 * Set when `status === "approved"`: the approve call's `nowMs`, in epoch
	 * milliseconds. `undefined` before. A poll checks this, not its own
	 * instant, against the subject's sessions boundary, so a revocation
	 * between approval and poll is honoured.
	 */
	readonly approvedAtMs: number | undefined;
	/**
	 * Set by an approval handed one: the approving session's `amr`, as device
	 * verification read it with `vouchedAmr`. `undefined` otherwise, which the
	 * grant reads as "cannot tell" and stamps no `amr` for.
	 */
	readonly amr: readonly string[] | undefined;
	/**
	 * Set by an approval handed one: when the approving session authenticated,
	 * in epoch milliseconds — never the approval's own instant. `undefined`
	 * otherwise, which the grant reads as "cannot tell" and stamps no
	 * `auth_time` for.
	 */
	readonly authTimeMs: number | undefined;
}

export type DeviceAuthorizationStatus = "pending" | "approved" | "denied";

/**
 * The outcome of one device poll: the RFC 8628 §3.5 states, plus `slow_down`
 * and `not_found` (answered as `invalid_grant`, indistinguishable from a
 * fabricated code).
 *
 * `approved` carries the record **and consumes it**, atomically with the
 * read (see the file header).
 */
export type DevicePollOutcome =
	| { readonly status: "not_found" }
	| { readonly status: "expired" }
	| { readonly status: "denied" }
	| { readonly status: "pending" }
	/** Polled too soon. `intervalSeconds` is the new, increased interval. */
	| { readonly status: "slow_down"; readonly intervalSeconds: number }
	| { readonly status: "approved"; readonly authorization: DeviceAuthorization };

export interface CreateDeviceAuthorizationInput {
	readonly deviceCode: string;
	readonly userCode: string;
	readonly clientId: string;
	/**
	 * `undefined` when the device asked for no scope. A required key: a
	 * writer that left it out would park a request that grants nothing.
	 */
	readonly requestedScope: readonly string[] | undefined;
	readonly expiresAtMs: number;
	readonly intervalSeconds: number;
}

/** Why an approval or denial did not apply. */
export type DeviceDecisionOutcome =
	| { readonly status: "ok"; readonly authorization: DeviceAuthorization }
	| { readonly status: "not_found" }
	| { readonly status: "expired" }
	/** Already approved or denied. A second decision must not overwrite the first. */
	| { readonly status: "already_decided"; readonly current: DeviceAuthorizationStatus };

export interface ApproveDeviceAuthorizationInput {
	readonly userCode: string;
	readonly subject: string;
	/**
	 * What the approval grants. **Omit it to grant `requestedScope`**, the
	 * normal case: that scope was already filtered against the client's
	 * allowlist when the device asked, and re-deriving it would open a window
	 * between what the user saw and what is granted. Pass it only to let the
	 * user *narrow*; adapters intersect with `requestedScope`, so it never
	 * widens.
	 */
	readonly grantedScope?: readonly string[];
	readonly nowMs: number;
	/**
	 * The approving session's `amr`, a non-empty list of non-empty strings,
	 * filled by device verification from the session it admitted. Omitted, the
	 * record holds none. Copied: the caller's array is not kept.
	 */
	readonly amr?: readonly string[];
	/**
	 * When the approving session authenticated: a valid `Date` at or after the
	 * epoch. Omitted, the record holds none.
	 */
	readonly authTime?: Date;
}

export interface DeviceCodeStore {
	/** Adapter identity, for logs and the boot report. */
	readonly kind: string;

	/**
	 * Register a new pending authorization.
	 *
	 * @throws `DeviceCodeStoreError` with `reason: "collision"` when
	 * `deviceCode` or `userCode` already has a live record, writing nothing
	 * (overwriting would detach a device from the code its user is about to
	 * approve). MUST use this reason: the endpoint re-draws for it only and
	 * answers any other error as a store outage (`503`).
	 * @throws `DeviceCodeStoreError` with `reason: "full"` when a bounded
	 * adapter is at its cap with every record live. Refuse, never evict:
	 * each record is a human's answer in flight. See `DeviceCodeStoreErrorReason`.
	 * @throws `RangeError`, recording nothing, when `expiresAtMs` is not a
	 * finite instant within the Date range (`isStorableExpiry`). A fractional
	 * `expiresAtMs` is valid.
	 */
	create(input: CreateDeviceAuthorizationInput): Promise<void>;

	/**
	 * Look up a live authorization by the code the human typed, without
	 * mutating it — for showing them what they are about to approve.
	 *
	 * Returns `null` for absent, expired, or already-decided codes: a code
	 * that cannot still be approved must not be displayed as if it could.
	 */
	findPendingByUserCode(userCode: string, nowMs: number): Promise<DeviceAuthorization | null>;

	/**
	 * Atomically move `pending` → `approved`, recording `amr` and `authTime`
	 * when handed them and neither otherwise.
	 *
	 * @throws `RangeError`, recording nothing, when `amr` is present and not a
	 * non-empty list of non-empty strings (`wellFormedAmr`), or `authTime` is
	 * present and not a valid `Date` at or after the epoch.
	 */
	approve(input: ApproveDeviceAuthorizationInput): Promise<DeviceDecisionOutcome>;

	/** Atomically move `pending` → `denied`. */
	deny(userCode: string, nowMs: number): Promise<DeviceDecisionOutcome>;

	/**
	 * Atomically: enforce the polling interval, read the status, and — when
	 * approved — consume the authorization so it cannot be redeemed twice.
	 *
	 * Adapters MUST NOT implement this as a read followed by a write. Two
	 * concurrent polls that both observe `approved` produce two access tokens
	 * from one human approval.
	 */
	poll(deviceCode: string, nowMs: number): Promise<DevicePollOutcome>;

	/** Drop a decided or expired record early. Absence is not an error. */
	remove(deviceCode: string): Promise<void>;
}

/**
 * Absence policy for the `deviceCodeStore` slot: an empty slot is a boot
 * failure naming the config key, not a runtime surprise on the first
 * `/oauth/device_authorization` request.
 *
 * Declaring absence is for a deployment that leaves the grant off; an
 * enabled grant without a store is refused by `deviceGrantModule`. The hint
 * is quoted into the boot error, so it must not tell an operator with the
 * grant enabled to write a line that is itself refused.
 */
export const DEVICE_CODE_STORE_ABSENCE_POLICY: AbsencePolicy = {
	configKey: ["device-grant", "store"],
	absentValue: "unsupported",
	hint:
		"the device authorization grant has nowhere to record a pending authorization, " +
		"so no device can ever be authorized. With device-grant.enabled = true " +
		"wire a store (memoryDeviceCodeStoreModule on a single replica, " +
		"redisDeviceCodeStoreModule otherwise) — the declaration is refused there; it is " +
		"for a deployment that leaves the grant off",
};

declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly deviceCodeStore?: DeviceCodeStore;
	}
}
