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
 * In-process `DeviceCodeStore`. Development and single-replica only.
 *
 * Declared replica-unsafe on its module's manifest (`replicaSafety`, #455): a
 * device that polls a different replica than the one holding its record is
 * told its code does not exist, and the human's approval lands on a replica
 * the device may never reach again.
 *
 * The atomicity the port demands is free here — JavaScript's single-threaded
 * event loop means the body of each method runs without interleaving — but
 * the *shape* still matters, because it is the shape a Redis adapter has to
 * reproduce in a script rather than discover it needed to.
 *
 * ### Bounded, three ways
 *
 * The first cut was unbounded in practice: the module built it with no
 * `sweepIntervalMs`, so the timer was null; `findPendingByUserCode`,
 * `approve` and `deny` answered "expired" without dropping the record; only
 * `poll` reclaimed. A device that asks for a code and never polls — or a
 * caller who asks for ten thousand — left records resident until exit.
 *
 * Same fix the access-token denylist got (#293 item 6), plus the cap the
 * rate limiter already had:
 *
 *   1. every read path drops an expired record it finds, so the ordinary
 *      traffic of a verification page reclaims as it goes;
 *   2. `create` — the one operation that grows the map — pays for the growth
 *      with an amortized sweep every `sweepInterval` creates, so a record
 *      nobody asks about again is reclaimed within one interval;
 *   3. `maxEntries` caps the resident set outright. At the cap, expired
 *      records are reclaimed first; if every resident record is still live,
 *      `create` refuses with `DeviceCodeStoreError { reason: "full" }`
 *      rather than evicting one.
 *
 * The optional timer stays for deployments that want zero-lag reclamation;
 * it is no longer what bounds the store.
 *
 * ### Why the cap refuses instead of evicting (#445)
 *
 * The first cut evicted the live record closest to expiry, on the argument
 * that it was the least harm — the one about to be reclaimed anyway. Under
 * the flood that actually reaches the cap that argument inverts: every
 * attacker record carries the newest expiry, so the records closest to
 * expiry are precisely the pre-existing ones — a human's pending approval,
 * an approval a device has not yet polled for — and all of them were
 * evicted before a single one of the attacker's. Roughly seventeen IPs at
 * the default 60/min reach 10 000 inside one 600 s code lifetime.
 *
 * The sibling caps evict because what they hold is reconstructible: an
 * evicted rate-limit bucket is a counter that resets, an evicted CRL cache
 * entry is a fetch that repeats. A device authorization is neither —
 * nothing can re-derive an approval the user already gave — so the answer
 * is the fail-closed one every other refusal in this repository gives: keep
 * what was issued, refuse what is new. The refused `create` comes from
 * `POST /oauth/device_authorization`, which sits behind the per-IP
 * rate-limit guard, so the flooder is the one told to come back later and a
 * legitimate device retries into a slot the next expiry frees. Evicting
 * same-`clientId` records first was considered and rejected: device clients
 * are public (RFC 8628 §5.6), so a flood is sent *as* the legitimate client,
 * and that policy would evict its real users first all the same.
 */

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
	requestedScope?: readonly string[];
	expiresAtMs: number;
	intervalSeconds: number;
	status: "pending" | "approved" | "denied";
	subject?: string;
	grantedScope?: readonly string[];
	lastPolledAtMs?: number;
}

const toAuthorization = (entry: Entry): DeviceAuthorization => ({
	userCode: entry.userCode,
	clientId: entry.clientId,
	...(entry.requestedScope ? { requestedScope: entry.requestedScope } : {}),
	expiresAtMs: entry.expiresAtMs,
	intervalSeconds: entry.intervalSeconds,
	status: entry.status,
	...(entry.subject === undefined ? {} : { subject: entry.subject }),
	...(entry.grantedScope ? { grantedScope: entry.grantedScope } : {}),
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
	 * Drop every record that can no longer be approved, plus any whose expiry
	 * is not a finite number: `NaN` and `Infinity` never satisfy
	 * `expiresAtMs <= now`, so without this they would sit in the map until
	 * process exit and, under a cap that refuses rather than evicts, hold a
	 * slot forever. A record that can never expire is the one least entitled
	 * to stay.
	 */
	const sweep = (nowMs: number): void => {
		for (const entry of [...byDeviceCode.values()]) {
			if (!Number.isFinite(entry.expiresAtMs) || entry.expiresAtMs <= nowMs) drop(entry);
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
			// A collision here is a generator failure, not traffic. Overwriting
			// would silently detach a device from the code its user is about to
			// approve — and hand the *new* device the old one's approval.
			if (byDeviceCode.has(input.deviceCode) || byUserCode.has(input.userCode)) {
				throw new Error("device authorization code collision");
			}
			createsSinceSweep += 1;
			// At most one O(n) pass per create (Copilot on #451). The amortized
			// cadence and the cap both want the same thing — expired records
			// gone before anything else is decided — and a second pass straight
			// after the first has nothing left to find. The interval therefore
			// counts creates since the last sweep, whichever reason ran it.
			if (createsSinceSweep >= sweepInterval || byDeviceCode.size >= maxEntries) {
				createsSinceSweep = 0;
				sweep(Date.now());
			}
			if (byDeviceCode.size >= maxEntries) {
				// Every resident record is live. See "Why the cap refuses
				// instead of evicting" in the file header (#445).
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
				...(input.requestedScope ? { requestedScope: input.requestedScope } : {}),
				expiresAtMs: input.expiresAtMs,
				intervalSeconds: input.intervalSeconds,
				status: "pending",
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
			const entry = livePendingByUserCode(input.userCode, input.nowMs);
			if (entry === null) return { status: "not_found" };
			if (entry === "expired") return { status: "expired" };
			if (entry.status !== "pending") {
				return { status: "already_decided", current: entry.status };
			}
			entry.status = "approved";
			entry.subject = input.subject;
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
