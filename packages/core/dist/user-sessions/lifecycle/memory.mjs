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
 * The in-process `SessionLifecycleStore`: one process's records, lost on a
 * restart, so it fences joins and closes within one replica only. Every
 * member checks and writes with no `await` between, so each is one step in
 * this process. A record lapses whole at its retention, judged on the
 * store's clock; a clock reading that is no instant within the Date range
 * fails the member with a `RangeError` and drops nothing. It holds at most
 * `maxEntries` records and `maxParticipants` per record. Full, it drops lapsed records and, if that makes no room,
 * evicts the `closed` record whose retention ends first; it rejects when
 * there is none. So a full store may drop a closed record before its
 * retention, which the session lifecycle allows: it closes a record only
 * after deleting its user session, and a join that adopts a session with no
 * record is refused unless the user session it read first is still there
 * once it has written (#1468), so a closed session is not joined again
 * through a record that left the store. A close repeated after the
 * eviction, or `federations`, then answers no snapshot, as after the
 * record's retention. An active or closing record is never evicted: that
 * would drop a live session's fence, or leave its close work undone; so a
 * loop whose closes stay pending still fills the store until their
 * retention. An `open` at capacity scans the store once.
 */
import { isStoreGeneration, newStoreGeneration, } from "../../adapters/conditionalWrite.mjs";
import { isStorableExpiry } from "../../adapters/expiry.mjs";
import { DEFAULT_CLOCK_SKEW_MS } from "../../jwt/verify.mjs";
import { MAX_MEMORY_STORE_ENTRIES, usableMaxEntries } from "../../single-use/max-entries.mjs";
import { checkSessionCloseItem, checkSessionCloseRequest, checkSessionExpiresAt, checkSessionLifecycleKey, checkSessionListingCursor, checkSessionListingLimit, checkSessionParticipant, compareSessionSids, } from "./readers.mjs";
import { sessionCloseItemOf, } from "./types.mjs";
export const DEFAULT_MEMORY_SESSION_LIFECYCLE_MAX_ENTRIES = 100_000;
export const DEFAULT_MEMORY_SESSION_LIFECYCLE_MAX_PARTICIPANTS = 1_000;
/** The record a stored entry holds, as a copy that shares nothing with it. */
const toRecord = (stored) => ({
    sub: stored.sub,
    state: stored.state,
    expiresAt: new Date(stored.expiresAtMs),
    participants: [...stored.participants.values()].map((p) => ({
        kind: p.kind,
        id: p.id,
        data: p.data,
    })),
    close: stored.close === undefined
        ? undefined
        : {
            cause: stored.close.cause,
            closingAt: new Date(stored.close.closingAtMs),
            pending: [...stored.close.pending],
        },
});
export function createInMemorySessionLifecycleStore(options = {}) {
    const owner = "createInMemorySessionLifecycleStore";
    const maxEntries = usableMaxEntries(options.maxEntries ?? DEFAULT_MEMORY_SESSION_LIFECYCLE_MAX_ENTRIES, owner);
    const maxParticipants = options.maxParticipants ?? DEFAULT_MEMORY_SESSION_LIFECYCLE_MAX_PARTICIPANTS;
    if (!Number.isInteger(maxParticipants) ||
        maxParticipants <= 0 ||
        maxParticipants > MAX_MEMORY_STORE_ENTRIES) {
        throw new RangeError(`${owner}: maxParticipants must be a whole number from 1 to ${MAX_MEMORY_STORE_ENTRIES} (got ${String(maxParticipants)})`);
    }
    const clock = options.now ?? Date.now;
    const records = new Map();
    const now = () => {
        const at = clock();
        if (!isStorableExpiry(at))
            throw new RangeError(`${owner}: the clock answered no instant within the Date range`);
        return at;
    };
    /** The live entry of `sid` at `at`; a lapsed one is dropped. */
    const live = (sid, at) => {
        const stored = records.get(sid);
        if (stored === undefined)
            return undefined;
        if (stored.retainUntilMs > at)
            return stored;
        records.delete(sid);
        return undefined;
    };
    return {
        kind: "memory",
        async open(sid, sub, expiresAt) {
            checkSessionLifecycleKey(sid, "sid");
            checkSessionLifecycleKey(sub, "sub");
            const expiresAtMs = checkSessionExpiresAt(expiresAt).getTime();
            const at = now();
            if (expiresAtMs <= at)
                return { outcome: "refused" };
            const stored = live(sid, at);
            if (stored !== undefined) {
                const same = stored.state === "active" && stored.sub === sub && stored.expiresAtMs === expiresAtMs;
                return { outcome: same ? "opened" : "refused" };
            }
            if (records.size >= maxEntries) {
                // One pass: drop the lapsed records, and note the closed record
                // whose retention ends first, the first held on a tie, to evict
                // only if dropping makes no room.
                let evictable;
                let evictableUntilMs = Number.POSITIVE_INFINITY;
                for (const [key, entry] of records) {
                    if (entry.retainUntilMs <= at) {
                        records.delete(key);
                    }
                    else if (entry.state === "closed" && entry.retainUntilMs < evictableUntilMs) {
                        evictable = key;
                        evictableUntilMs = entry.retainUntilMs;
                    }
                }
                if (records.size >= maxEntries) {
                    if (evictable === undefined) {
                        throw new Error(`${owner}: full at ${maxEntries} records, none of them closed; nothing was written`);
                    }
                    records.delete(evictable);
                }
            }
            records.set(sid, {
                sub,
                expiresAtMs,
                state: "active",
                participants: new Map(),
                close: undefined,
                retainUntilMs: expiresAtMs + DEFAULT_CLOCK_SKEW_MS,
                generation: newStoreGeneration(),
            });
            return { outcome: "opened" };
        },
        async join(sid, participant) {
            checkSessionLifecycleKey(sid, "sid");
            const joining = checkSessionParticipant(participant);
            const at = now();
            const stored = live(sid, at);
            if (stored === undefined)
                return { outcome: "missing" };
            if (stored.state !== "active" || stored.expiresAtMs <= at)
                return { outcome: "closed" };
            const item = sessionCloseItemOf(joining);
            if (!stored.participants.has(item) && stored.participants.size >= maxParticipants) {
                throw new Error(`${owner}: a record holds at most ${maxParticipants} participants; nothing was written`);
            }
            stored.participants.set(item, { kind: joining.kind, id: joining.id, data: joining.data });
            stored.generation = newStoreGeneration();
            return { outcome: "joined" };
        },
        async beginClose(sid, request) {
            checkSessionLifecycleKey(sid, "sid");
            const { cause, steps, perParticipant, retainMs } = checkSessionCloseRequest(request);
            const at = now();
            const stored = live(sid, at);
            if (stored === undefined)
                return { outcome: "missing" };
            if (stored.state === "active") {
                const pending = new Set(steps);
                for (const [item, p] of stored.participants)
                    if (perParticipant.includes(p.kind))
                        pending.add(item);
                stored.state = pending.size > 0 ? "closing" : "closed";
                stored.close = { cause, closingAtMs: at, pending };
                stored.retainUntilMs = Math.max(stored.retainUntilMs, at + retainMs);
                stored.generation = newStoreGeneration();
            }
            return {
                outcome: stored.state === "closing" ? "closing" : "closed",
                generation: stored.generation,
                record: toRecord(stored),
            };
        },
        async completeIf(sid, expected, item) {
            checkSessionLifecycleKey(sid, "sid");
            checkSessionCloseItem(item);
            if (!isStoreGeneration(expected)) {
                throw new RangeError(`${owner}: expected is no well-formed generation; nothing was written`);
            }
            const stored = live(sid, now());
            if (stored === undefined)
                return { outcome: "missing" };
            if (stored.generation !== expected)
                return { outcome: "conflict" };
            if (stored.close === undefined || !stored.close.pending.has(item)) {
                throw new RangeError(`${owner}: ${item} is not pending; nothing was written`);
            }
            stored.close.pending.delete(item);
            if (stored.close.pending.size === 0)
                stored.state = "closed";
            stored.generation = newStoreGeneration();
            return { outcome: "updated", generation: stored.generation };
        },
        async read(sid) {
            checkSessionLifecycleKey(sid, "sid");
            const stored = live(sid, now());
            return stored === undefined
                ? null
                : { value: toRecord(stored), generation: stored.generation };
        },
        async listClosing(limit, after = "") {
            checkSessionListingLimit(limit);
            checkSessionListingCursor(after);
            const at = now();
            const closing = [];
            for (const [sid, stored] of records) {
                if (stored.retainUntilMs <= at)
                    records.delete(sid);
                else if (stored.state === "closing" && compareSessionSids(after, sid) < 0)
                    closing.push(sid);
            }
            return closing.sort(compareSessionSids).slice(0, limit);
        },
    };
}
