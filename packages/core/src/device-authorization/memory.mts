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
 * In-process `DeviceCodeStore`. Development and single-replica only: a device
 * polling a replica other than the one holding its record is told its code
 * does not exist (declared replica-unsafe on the module manifest).
 *
 * Methods run without interleaving on the event loop, but keep the shape a
 * Redis adapter must reproduce atomically in a script.
 *
 * Bounded three ways: every read path drops an expired record it finds;
 * `create` runs an amortized sweep every `sweepInterval` creates; `maxEntries`
 * caps the resident set. The optional timer only adds zero-lag reclamation.
 *
 * At the cap, `create` refuses (`DeviceCodeStoreError { reason: "full" }`)
 * rather than evicting. Under a flood every attacker record carries the newest
 * expiry, so evicting "closest to expiry" drops legitimate pending approvals
 * first, and unlike a rate-limit bucket or a cache entry an approval cannot be
 * reconstructed. The refused request sits behind the per-IP rate limit, so the
 * flooder is the one told to retry. Evicting by `clientId` does not help:
 * device clients are public (RFC 8628 §5.6), so a flood arrives as the
 * legitimate client.
 */

import { isStorableExpiry } from "../adapters/expiry.mjs";
import { recordableDeviceApproval } from "./approval.mjs";
import { DeviceCodeStoreError } from "./errors.mjs";
import type {
	ApproveDeviceAuthorizationInput,
	CreateDeviceAuthorizationInput,
	DeviceAuthorization,
	DeviceCodeStore,
	DeviceDecisionOutcome,
	DevicePollOutcome,
} from "./types.mjs";

interface Entry {
	deviceCode: string;
	userCode: string;
	clientId: string;
	requestedScope: readonly string[] | undefined;
	expiresAtMs: number;
	intervalSeconds: number;
	status: "pending" | "approved" | "denied";
	subject: string | undefined;
	grantedScope: readonly string[] | undefined;
	approvedAtMs: number | undefined;
	amr: readonly string[] | undefined;
	authTimeMs: number | undefined;
	lastPolledAtMs?: number;
}

const toAuthorization = (entry: Entry): DeviceAuthorization => ({
	userCode: entry.userCode,
	clientId: entry.clientId,
	requestedScope: entry.requestedScope,
	expiresAtMs: entry.expiresAtMs,
	intervalSeconds: entry.intervalSeconds,
	status: entry.status,
	subject: entry.subject,
	grantedScope: entry.grantedScope,
	approvedAtMs: entry.approvedAtMs,
	amr: entry.amr,
	authTimeMs: entry.authTimeMs,
});

/**
 * How much a too-fast poll adds to the interval.
 *
 * RFC 8628 §3.5 defines `slow_down` as "the interval MUST be increased by 5
 * seconds for this and all subsequent requests". The RFC addresses that to the
 * client, but a server that says `slow_down` while continuing to measure
 * against the original interval is asking for a change it does not itself
 * observe — a compliant client would then be told to slow down forever.
 */
const SLOW_DOWN_INCREMENT_SECONDS = 5;

/**
 * Ceiling on resident records. Ten thousand pending device authorizations is
 * far past what a single-replica deployment serves in one code lifetime, and
 * at a few hundred bytes each it is a bound an operator never notices.
 */
export const DEFAULT_MEMORY_DEVICE_CODE_STORE_MAX_ENTRIES = 10_000;

/**
 * `create` calls between amortized sweeps. A sweep is O(size), and every
 * create is one rate-limited HTTP request, so the cost per request stays
 * constant while the resident set is bounded at "live records, plus at most
 * one interval of expired ones".
 */
export const DEFAULT_MEMORY_DEVICE_CODE_STORE_SWEEP_INTERVAL = 1_000;

export interface MemoryDeviceCodeStoreOptions {
	/**
	 * How often to sweep expired entries on a timer, in milliseconds. Off by
	 * default: the amortized sweep on `create` and the reclaim-on-read paths
	 * already bound the store, so the timer buys only zero-lag reclamation.
	 */
	readonly sweepIntervalMs?: number;
	/**
	 * Ceiling on resident records. A non-integer or non-positive value falls
	 * back to the default rather than removing the cap — `0` is what an empty
	 * environment variable coerces to.
	 */
	readonly maxEntries?: number;
	/**
	 * `create` calls between amortized sweeps. Same fallback rule as
	 * `maxEntries`: a bad value must not disable the sweep.
	 */
	readonly sweepInterval?: number;
}

const positiveIntegerOr = (value: number | undefined, fallback: number): number =>
	typeof value === "number" && Number.isInteger(value) && value > 0 ? value : fallback;

export interface MemoryDeviceCodeStore extends DeviceCodeStore {
	/** Entry count, for tests and for the sweep's own coverage. */
	size(): number;
	/** Stop the sweep timer. */
	dispose(): void;
}

export const createMemoryDeviceCodeStore = (
	options: MemoryDeviceCodeStoreOptions = {},
): MemoryDeviceCodeStore => {
	const byDeviceCode = new Map<string, Entry>();
	const byUserCode = new Map<string, Entry>();
	const maxEntries = positiveIntegerOr(
		options.maxEntries,
		DEFAULT_MEMORY_DEVICE_CODE_STORE_MAX_ENTRIES,
	);
	const sweepInterval = positiveIntegerOr(
		options.sweepInterval,
		DEFAULT_MEMORY_DEVICE_CODE_STORE_SWEEP_INTERVAL,
	);
	let createsSinceSweep = 0;

	const drop = (entry: Entry): void => {
		byDeviceCode.delete(entry.deviceCode);
		byUserCode.delete(entry.userCode);
	};

	/**
	 * Drop every record that can no longer be approved. Every resident expiry
	 * is a finite number — `create` refuses any other, since `NaN` and
	 * `Infinity` never satisfy `expiresAtMs <= now` and such a record would sit
	 * in the map until process exit, holding a slot under a cap that refuses
	 * rather than evicts.
	 */
	const sweep = (nowMs: number): void => {
		for (const entry of [...byDeviceCode.values()]) {
			if (entry.expiresAtMs <= nowMs) drop(entry);
		}
	};

	/** Read-path reclamation: an expired record is dropped by whoever finds it. */
	const livePendingByUserCode = (userCode: string, nowMs: number): Entry | "expired" | null => {
		const entry = byUserCode.get(userCode);
		if (entry === undefined) return null;
		if (entry.expiresAtMs <= nowMs) {
			drop(entry);
			return "expired";
		}
		return entry;
	};

	const timer =
		options.sweepIntervalMs === undefined
			? null
			: setInterval(() => sweep(Date.now()), options.sweepIntervalMs);
	timer?.unref?.();

	return {
		kind: "memory",
		size: () => byDeviceCode.size,
		dispose: () => {
			if (timer !== null) clearInterval(timer);
		},

		create: async (input: CreateDeviceAuthorizationInput) => {
			// NaN is never `<= now`: such a record read as pending, and held a
			// slot under the cap, until a sweep found it. A caller fault, and
			// refused here so that no resident record can carry one.
			if (!isStorableExpiry(input.expiresAtMs)) {
				throw new RangeError(
					`DeviceCodeStore.create: expiresAtMs must be a finite instant within the Date range (got ${String(input.expiresAtMs)})`,
				);
			}
			// A collision here is a generator failure, not traffic. Overwriting
			// would silently detach a device from the code its user is about to
			// approve — and hand the *new* device the old one's approval.
			if (byDeviceCode.has(input.deviceCode) || byUserCode.has(input.userCode)) {
				throw new DeviceCodeStoreError({
					reason: "collision",
					message: "device authorization code collision",
				});
			}
			createsSinceSweep += 1;
			// At most one O(n) pass per create: the cadence and the cap both want
			// expired records gone first, so the interval counts creates since the
			// last sweep, whichever reason ran it.
			if (createsSinceSweep >= sweepInterval || byDeviceCode.size >= maxEntries) {
				createsSinceSweep = 0;
				sweep(Date.now());
			}
			if (byDeviceCode.size >= maxEntries) {
				// Every resident record is live: refuse rather than evict (see the
				// file header).
				throw new DeviceCodeStoreError({
					reason: "full",
					message:
						`memory DeviceCodeStore is at its cap of ${maxEntries} live device ` +
						"authorizations; refusing this one rather than evicting one already issued",
				});
			}
			const entry: Entry = {
				deviceCode: input.deviceCode,
				userCode: input.userCode,
				clientId: input.clientId,
				// Truthiness: an untyped caller's `null`, `""` or `false` is "no
				// scope", as the Redis store reads it. An array, empty included, is kept.
				requestedScope: input.requestedScope ? input.requestedScope : undefined,
				expiresAtMs: input.expiresAtMs,
				intervalSeconds: input.intervalSeconds,
				status: "pending",
				subject: undefined,
				grantedScope: undefined,
				approvedAtMs: undefined,
				amr: undefined,
				authTimeMs: undefined,
			};
			byDeviceCode.set(entry.deviceCode, entry);
			byUserCode.set(entry.userCode, entry);
		},

		findPendingByUserCode: async (userCode: string, nowMs: number) => {
			const entry = livePendingByUserCode(userCode, nowMs);
			if (entry === null || entry === "expired") return null;
			if (entry.status !== "pending") return null;
			return toAuthorization(entry);
		},

		approve: async (input: ApproveDeviceAuthorizationInput): Promise<DeviceDecisionOutcome> => {
			// Refused before the lookup, so a refused approval changes nothing.
			const { amr, authTimeMs } = recordableDeviceApproval(input, input.nowMs);
			const entry = livePendingByUserCode(input.userCode, input.nowMs);
			if (entry === null) return { status: "not_found" };
			if (entry === "expired") return { status: "expired" };
			if (entry.status !== "pending") {
				return { status: "already_decided", current: entry.status };
			}
			entry.status = "approved";
			entry.subject = input.subject;
			entry.approvedAtMs = input.nowMs;
			entry.amr = amr;
			entry.authTimeMs = authTimeMs;
			// Omitted means "grant what was asked for". When supplied it is
			// intersected rather than trusted: a caller may narrow what the
			// user approved, never widen it past the allowlist the device
			// authorization endpoint already applied.
			const requested = entry.requestedScope ?? [];
			entry.grantedScope =
				input.grantedScope === undefined
					? requested
					: input.grantedScope.filter((s) => requested.includes(s));
			return { status: "ok", authorization: toAuthorization(entry) };
		},

		deny: async (userCode: string, nowMs: number): Promise<DeviceDecisionOutcome> => {
			const entry = livePendingByUserCode(userCode, nowMs);
			if (entry === null) return { status: "not_found" };
			if (entry === "expired") return { status: "expired" };
			if (entry.status !== "pending") {
				return { status: "already_decided", current: entry.status };
			}
			entry.status = "denied";
			return { status: "ok", authorization: toAuthorization(entry) };
		},

		poll: async (deviceCode: string, nowMs: number): Promise<DevicePollOutcome> => {
			const entry = byDeviceCode.get(deviceCode);
			if (entry === undefined) return { status: "not_found" };
			if (entry.expiresAtMs <= nowMs) {
				drop(entry);
				return { status: "expired" };
			}

			// The interval gate runs before the status read, so a device that
			// polls too fast is told to slow down whether or not its user has
			// answered yet. Reporting `approved` to an over-eager poller would
			// reward the behaviour the interval exists to discourage.
			const last = entry.lastPolledAtMs;
			if (last !== undefined && nowMs - last < entry.intervalSeconds * 1000) {
				entry.intervalSeconds += SLOW_DOWN_INCREMENT_SECONDS;
				entry.lastPolledAtMs = nowMs;
				return { status: "slow_down", intervalSeconds: entry.intervalSeconds };
			}
			entry.lastPolledAtMs = nowMs;

			if (entry.status === "denied") {
				drop(entry);
				return { status: "denied" };
			}
			if (entry.status === "pending") return { status: "pending" };

			// Approved: consume here, in the same turn as the read, so a second
			// poll cannot redeem the same approval.
			drop(entry);
			return { status: "approved", authorization: toAuthorization(entry) };
		},

		remove: async (deviceCode: string) => {
			const entry = byDeviceCode.get(deviceCode);
			if (entry !== undefined) drop(entry);
		},
	};
};
