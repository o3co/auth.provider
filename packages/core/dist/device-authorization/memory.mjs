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
const toAuthorization = (entry) => ({
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
const positiveIntegerOr = (value, fallback) => typeof value === "number" && Number.isInteger(value) && value > 0 ? value : fallback;
export const createMemoryDeviceCodeStore = (options = {}) => {
    const byDeviceCode = new Map();
    const byUserCode = new Map();
    const maxEntries = positiveIntegerOr(options.maxEntries, DEFAULT_MEMORY_DEVICE_CODE_STORE_MAX_ENTRIES);
    const sweepInterval = positiveIntegerOr(options.sweepInterval, DEFAULT_MEMORY_DEVICE_CODE_STORE_SWEEP_INTERVAL);
    let createsSinceSweep = 0;
    const drop = (entry) => {
        byDeviceCode.delete(entry.deviceCode);
        byUserCode.delete(entry.userCode);
    };
    const sweep = (nowMs) => {
        for (const entry of [...byDeviceCode.values()]) {
            if (entry.expiresAtMs <= nowMs)
                drop(entry);
        }
    };
    /**
     * Evict the record closest to expiry. A non-finite `expiresAtMs` compares
     * false against everything, so it is dropped on sight rather than left to
     * win every comparison — that is what keeps the caller's
     * `while (size >= max)` loop making progress. The loop only runs on a
     * non-empty map, so one of the two branches always drops something.
     */
    const evictEarliestExpiring = () => {
        let victim;
        for (const entry of byDeviceCode.values()) {
            if (!Number.isFinite(entry.expiresAtMs)) {
                drop(entry);
                return;
            }
            if (victim === undefined || entry.expiresAtMs < victim.expiresAtMs)
                victim = entry;
        }
        if (victim !== undefined)
            drop(victim);
    };
    /** Read-path reclamation: an expired record is dropped by whoever finds it. */
    const livePendingByUserCode = (userCode, nowMs) => {
        const entry = byUserCode.get(userCode);
        if (entry === undefined)
            return null;
        if (entry.expiresAtMs <= nowMs) {
            drop(entry);
            return "expired";
        }
        return entry;
    };
    const timer = options.sweepIntervalMs === undefined
        ? null
        : setInterval(() => sweep(Date.now()), options.sweepIntervalMs);
    timer?.unref?.();
    return {
        kind: "memory",
        size: () => byDeviceCode.size,
        dispose: () => {
            if (timer !== null)
                clearInterval(timer);
        },
        create: async (input) => {
            // A collision here is a generator failure, not traffic. Overwriting
            // would silently detach a device from the code its user is about to
            // approve — and hand the *new* device the old one's approval.
            if (byDeviceCode.has(input.deviceCode) || byUserCode.has(input.userCode)) {
                throw new Error("device authorization code collision");
            }
            createsSinceSweep += 1;
            if (createsSinceSweep >= sweepInterval) {
                createsSinceSweep = 0;
                sweep(Date.now());
            }
            if (byDeviceCode.size >= maxEntries) {
                sweep(Date.now());
                while (byDeviceCode.size >= maxEntries)
                    evictEarliestExpiring();
            }
            const entry = {
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
        findPendingByUserCode: async (userCode, nowMs) => {
            const entry = livePendingByUserCode(userCode, nowMs);
            if (entry === null || entry === "expired")
                return null;
            if (entry.status !== "pending")
                return null;
            return toAuthorization(entry);
        },
        approve: async (input) => {
            const entry = livePendingByUserCode(input.userCode, input.nowMs);
            if (entry === null)
                return { status: "not_found" };
            if (entry === "expired")
                return { status: "expired" };
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
        deny: async (userCode, nowMs) => {
            const entry = livePendingByUserCode(userCode, nowMs);
            if (entry === null)
                return { status: "not_found" };
            if (entry === "expired")
                return { status: "expired" };
            if (entry.status !== "pending") {
                return { status: "already_decided", current: entry.status };
            }
            entry.status = "denied";
            return { status: "ok", authorization: toAuthorization(entry) };
        },
        poll: async (deviceCode, nowMs) => {
            const entry = byDeviceCode.get(deviceCode);
            if (entry === undefined)
                return { status: "not_found" };
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
            if (entry.status === "pending")
                return { status: "pending" };
            // Approved: consume here, in the same turn as the read, so a second
            // poll cannot redeem the same approval.
            drop(entry);
            return { status: "approved", authorization: toAuthorization(entry) };
        },
        remove: async (deviceCode) => {
            const entry = byDeviceCode.get(deviceCode);
            if (entry !== undefined)
                drop(entry);
        },
    };
};
