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
 * The in-process {@link MfaFactorStore}, for development and a single replica.
 * Records fork per replica and vanish on restart, after which every subject
 * reads as having nothing enrolled; the enrollment witness catches that loss.
 *
 * Each operation is one synchronous `Map` step, so atomic: no `await` falls
 * between a check and its write, and the reset is serialised with the
 * conditional writes. So its write lifetime W (docs/adapter-surface.md,
 * "Conditional writes", rule 6) is 0. Records are copied in and out: changing
 * a returned or written record changes nothing kept here.
 *
 * A subject's set is an entry holding its records and its store generation,
 * minted with `newStoreGeneration` at every membership write. The first
 * membership write makes it. A set emptied by any membership write (its last
 * removal or a reset) is left as the set's tombstone, which expires on the
 * store's clock `BUNDLED_STORE_WRITE_LIFETIME_MS` after that write; a write
 * that leaves it holding a record takes the expiry off. An expired tombstone
 * reads as absent, and is deleted when next read or written, or by the sweep,
 * paced as the replay seen-set's (`single-use/sweep.mts`) on membership
 * writes. Every entry holds a generation from the write that made it, so no
 * set here is ever without one and `listVersioned` has nothing to mint. One
 * process is one instance, so a second instance on the same backend is this
 * one.
 */
import { BUNDLED_STORE_WRITE_LIFETIME_MS, isStoreGeneration, newStoreGeneration, } from "../adapters/conditionalWrite.mjs";
import { createAmortizedSweep } from "../single-use/sweep.mjs";
import { checkMfaVersionAdvances } from "./version.mjs";
/** Membership writes between two sweeps of expired tombstones. */
const SWEEP_INTERVAL = 1_000;
/** The least time between two sweeps, in milliseconds. */
const MIN_SWEEP_INTERVAL_MS = 10_000;
/** The record as plain data, every field named, its dates copied. */
const copyOf = (record) => ({
    id: record.id,
    subject: record.subject,
    kind: record.kind,
    label: record.label,
    binding: record.binding,
    createdAt: new Date(record.createdAt.getTime()),
    lastUsedAt: record.lastUsedAt === undefined ? undefined : new Date(record.lastUsedAt.getTime()),
    version: record.version,
    data: record.data,
});
export function createMemoryMfaFactorStore(options = {}) {
    const now = options.now ?? Date.now;
    const schedule = createAmortizedSweep({}, { sweepInterval: SWEEP_INTERVAL, minSweepIntervalMs: MIN_SWEEP_INTERVAL_MS }, "memory MfaFactorStore");
    const bySubject = new Map();
    const expired = (set, nowMs) => set.expiresAtMs !== undefined && set.expiresAtMs <= nowMs;
    /** `subject`'s set, unless it is none or a tombstone past its expiry, which it deletes. */
    const live = (subject) => {
        const set = bySubject.get(subject);
        if (set === undefined || !expired(set, now()))
            return set;
        bySubject.delete(subject);
        return undefined;
    };
    /**
     * `change` applied to `subject`'s set, made when it has none, at a new
     * generation, and with a tombstone's expiry when it is left empty: every
     * membership write's one step.
     */
    const written = (subject, change) => {
        const nowMs = now();
        const set = live(subject) ?? {
            records: new Map(),
            generation: newStoreGeneration(),
            expiresAtMs: undefined,
        };
        change(set.records);
        set.generation = newStoreGeneration();
        set.expiresAtMs = set.records.size === 0 ? nowMs + BUNDLED_STORE_WRITE_LIFETIME_MS : undefined;
        bySubject.set(subject, set);
        if (schedule.wrote()) {
            for (const [other, held] of bySubject) {
                if (expired(held, nowMs))
                    bySubject.delete(other);
            }
        }
        return set;
    };
    return {
        kind: "memory",
        async list(subject) {
            return [...(live(subject)?.records.values() ?? [])].map(copyOf);
        },
        async listVersioned(subject) {
            const set = live(subject);
            return set === undefined
                ? { generation: null, items: [] }
                : { generation: set.generation, items: [...set.records.values()].map(copyOf) };
        },
        async createIf(record, expected) {
            if (expected !== null && !isStoreGeneration(expected)) {
                throw new RangeError("MfaFactorStore.createIf: expected is not a store generation");
            }
            const set = live(record.subject);
            const atExpected = expected === null ? set === undefined : set?.generation === expected;
            if (!atExpected || set?.records.has(record.id) === true)
                return { outcome: "conflict" };
            const { generation } = written(record.subject, (records) => records.set(record.id, copyOf(record)));
            return { outcome: "created", generation };
        },
        async removeIf(subject, id, expected) {
            if (!isStoreGeneration(expected)) {
                throw new RangeError("MfaFactorStore.removeIf: expected is not a store generation");
            }
            const set = live(subject);
            if (set === undefined)
                return { outcome: "missing" };
            if (set.generation !== expected)
                return { outcome: "conflict" };
            if (!set.records.has(id))
                return { outcome: "missing" };
            const { generation } = written(subject, (records) => records.delete(id));
            return { outcome: "removed", generation };
        },
        async update(subject, id, expectedVersion, next) {
            checkMfaVersionAdvances(expectedVersion, "MfaFactorStore.update");
            const records = live(subject)?.records;
            const current = records?.get(id);
            if (records === undefined || current === undefined || current.version !== expectedVersion) {
                return null;
            }
            const updated = copyOf({
                ...current,
                data: next.data,
                label: next.label,
                lastUsedAt: next.lastUsedAt,
                version: current.version + 1,
            });
            records.set(id, updated);
            return copyOf(updated);
        },
        async removeAllForSubject(subject) {
            written(subject, (records) => records.clear());
        },
    };
}
