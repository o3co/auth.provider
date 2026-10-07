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
 * A subject's first-binding mark as this package notes and reads it (the
 * MFA ADR's D12; core's `MfaTransactionStore.noteFirstBinding` and
 * `firstBindingAt`): how long a noted mark stands, how a store's answer is
 * read, and which authentication a mark distrusts.
 *
 * - A mark stands `max(mfa.manage.maxAgeSeconds, 2 × mfa.transactionTtlSeconds)`,
 *   twice `DEFAULT_CLOCK_SKEW_MS` and one factor-set lease: the longest a
 *   session (its recent primary) or a continuation (one reopen) it distrusts
 *   can still bind, with the skew once for the clock that dated the
 *   authentication and once for the store's clock that ends the mark, and the
 *   lease a write it marks may still be landing in.
 * - An authentication at or before the mark plus `DEFAULT_CLOCK_SKEW_MS` and
 *   one factor-set lease is distrusted — a sign-in made while the marked write
 *   may still have been landing, on a clock up to the skew ahead — and so is
 *   one whose time cannot be read; a fresh one is not until that has passed
 *   (`retryAfterMs`). Every reader judges by the same mark
 *   (`createFirstBindingMark`), which holds the lease: none passes it.
 * - An answer the port does not promise is an outage, never "no mark".
 */
import { DEFAULT_CLOCK_SKEW_MS, readFirstBindingAt } from "@o3co/auth-provider-core";
import { checkFactorSetStoreTimeout, leaseMsFor } from "./factorSet.mjs";
/** A window setting, as a whole number of seconds from 1; else a `RangeError` naming it. */
const checkWindowSeconds = (value, name) => {
    if (!Number.isSafeInteger(value) || value < 1) {
        throw new RangeError(`${name}: ${String(value)} is not a whole number of seconds from 1`);
    }
    return value;
};
/** `settings` checked, with the factor-set lease its `storeTimeoutMs` makes. */
const readSettings = (settings) => {
    const manage = checkWindowSeconds(settings.manageMaxAgeSeconds, "mfa.manage.maxAgeSeconds");
    const transaction = checkWindowSeconds(settings.transactionTtlSeconds, "mfa.transactionTtlSeconds");
    return {
        windowMs: Math.max(manage, 2 * transaction) * 1000,
        leaseMs: leaseMsFor(checkFactorSetStoreTimeout(settings.storeTimeoutMs)),
    };
};
/** How long a mark noted now stands, in whole milliseconds (see this file's header). */
export function firstBindingMarkLifetimeMs(settings) {
    const { windowMs, leaseMs } = readSettings(settings);
    return windowMs + 2 * DEFAULT_CLOCK_SKEW_MS + leaseMs;
}
/**
 * What `firstBindingAt(subject, nowMs)` answered, read through core's
 * `readFirstBindingAt`: the mark's time, or `null` for none. Throws a
 * `TypeError` for anything else.
 */
export function readFirstBindingMark(answer, nowMs) {
    const read = readFirstBindingAt(answer, nowMs);
    if (read === undefined) {
        throw new TypeError("MfaTransactionStore.firstBindingAt answered something that is not a time or null");
    }
    return read;
}
/** The latest authentication a mark at `markAtMs` distrusts: the mark, the skew and the lease. */
const distrustedUntil = (markAtMs, leaseMs) => markAtMs + DEFAULT_CLOCK_SKEW_MS + leaseMs;
/** Whether a mark at `markAtMs` distrusts an authentication at `authTimeMs` (`FirstBindingMark.distrusts`). */
function distrustedByFirstBinding(authTimeMs, markAtMs, leaseMs) {
    if (markAtMs === null)
        return false;
    return !(typeof authTimeMs === "number" && authTimeMs > distrustedUntil(markAtMs, leaseMs));
}
/** The mark over `settings` (see this file's header); a setting out of its range is a `RangeError` naming it. */
export function createFirstBindingMark(settings) {
    const lifetimeMs = firstBindingMarkLifetimeMs(settings);
    const { leaseMs } = readSettings(settings);
    return Object.freeze({
        lifetimeMs,
        readCoversMs: lifetimeMs - DEFAULT_CLOCK_SKEW_MS - leaseMs,
        distrusts: (authTimeMs, markAtMs) => distrustedByFirstBinding(authTimeMs, markAtMs, leaseMs),
        retryAfterMs: (markAtMs, nowMs) => Math.max(0, distrustedUntil(markAtMs, leaseMs) + 1 - nowMs),
    });
}
