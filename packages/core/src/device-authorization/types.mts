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
 * Authorization Grant (RFC 8628, #298).
 *
 * The grant spans two devices and three requests that arrive out of order: a
 * device asks for a code, a human approves it somewhere else, and the device
 * discovers this by polling. Every one of those steps is a race with the
 * others, so the port is written as **atomic operations rather than
 * read-then-write pairs** — `approve`, `deny` and `poll` each collapse their
 * check and their mutation into one call the adapter must perform
 * indivisibly.
 *
 * That shape is not decoration. A `find` + `update` version of `poll` lets two
 * concurrent polls both observe `approved` and both redeem the code, which
 * turns a single user approval into two access tokens.
 */

import type { AbsencePolicy } from "../modules/manifest/absence-policy.mjs";

/**
 * What the authorization server knows about one device authorization.
 *
 * `deviceCode` is absent from this record on purpose: it is the device's
 * bearer credential and the only thing that redeems the grant, so it is a
 * lookup key rather than a field to hand back. Adapters that must persist it
 * do so under their own key space.
 */
export interface DeviceAuthorization {
	/** The code the human types. Normalised — see `normaliseUserCode`. */
	readonly userCode: string;
	readonly clientId: string;
	/** Scope the device asked for, before any policy narrowing. */
	readonly requestedScope?: readonly string[];
	readonly expiresAtMs: number;
	/** Minimum seconds between polls, as advertised to the device. */
	readonly intervalSeconds: number;
	readonly status: DeviceAuthorizationStatus;
	/** Set when `status === "approved"`: who approved it. */
	readonly subject?: string;
	/** Set when `status === "approved"`: what they approved. */
	readonly grantedScope?: readonly string[];
}

export type DeviceAuthorizationStatus = "pending" | "approved" | "denied";

/**
 * The outcome of one device poll.
 *
 * These are the states RFC 8628 §3.5 names, plus the two the RFC leaves to the
 * server: `slow_down` (the device polled faster than the interval it was
 * given) and `not_found` (which the token endpoint answers as
 * `invalid_grant`, indistinguishable from a fabricated code).
 *
 * `approved` carries the record **and consumes it**. Single-use is the
 * adapter's job because it must be atomic with the read — see the file
 * header.
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
	readonly requestedScope?: readonly string[];
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
	 * What the approval grants. **Omit it to grant `requestedScope`**, which
	 * is the normal case and the safe default.
	 *
	 * The scope is settled and filtered against the client's allowlist when
	 * the device first asks, so by approval time it is already the answer.
	 * Re-deriving it here would mean a second read of the record between the
	 * lookup that showed the user a scope and the write that grants one —
	 * a window in which those two can differ. Passing it explicitly is for
	 * a deployment that lets the user *narrow* what they approve; it can
	 * never widen, because adapters intersect with `requestedScope`.
	 */
	readonly grantedScope?: readonly string[];
	readonly nowMs: number;
}

export interface DeviceCodeStore {
	/** Adapter identity, for logs and the boot report. */
	readonly kind: string;

	/**
	 * Register a new pending authorization.
	 *
	 * @throws when `deviceCode` or `userCode` already has a live record. A
	 * collision is a generator failure, not a routine condition, and silently
	 * overwriting would detach a device from the code its user is about to
	 * approve.
	 * @throws `DeviceCodeStoreError` with `reason: "full"` when a bounded
	 * adapter is at its cap with every resident record live (#445). An
	 * adapter refuses rather than evicts here: what it holds is a human's
	 * answer in flight, and the caller can ask again while the user cannot
	 * re-approve what they never saw fail.
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

	/** Atomically move `pending` → `approved`. */
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
 * Absence policy for the `deviceCodeStore` slot (#363 discipline).
 *
 * Optional to wire, not optional to decide: a composition that mounts the
 * device grant without a store has no way to remember that a device is
 * waiting, so the grant cannot work at all. The policy makes that a boot
 * failure with a config key to set rather than a runtime surprise on the
 * first `/oauth/device_authorization` request.
 */
export const DEVICE_CODE_STORE_ABSENCE_POLICY: AbsencePolicy = {
	configKey: ["oauth", "deviceAuthorization", "store"],
	absentValue: "unsupported",
	hint:
		"the device authorization grant has nowhere to record a pending authorization, " +
		"so no device can ever be authorized — every /oauth/device_authorization request " +
		"would fail at runtime instead of at boot",
};

declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly deviceCodeStore?: DeviceCodeStore;
	}
}
