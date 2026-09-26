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
/** Whatever happened, it happened; see `drain`'s contract below. */
const swallow = () => undefined;
export function createFederationGrantBackground() {
    /**
     * Both kinds of outstanding thing, as promises: registered work, and one
     * promise per admitted operation that its release resolves. Holding them
     * in one set is what lets the drain treat "a request that has not answered"
     * and "a write that has not landed" as the same question.
     */
    const pending = new Set();
    let closing = false;
    let draining;
    const track = (work) => {
        // Neither outcome is this registry's to have an opinion about. Core
        // promises what it hands over never rejects and reports its own
        // failures through `report`; a hand-mounted handler has no such
        // discipline, and the answer the tail belongs to was sent long ago, so
        // failing the shutdown over it would be an AggregateError for something
        // nobody is waiting for.
        const entry = work.then(swallow, swallow);
        pending.add(entry);
        // For the process that never shuts down: a provider serving traffic
        // registers a tail per refresh, and a set nothing is ever removed from
        // is a leak. The drain does not depend on this — it forgets what it has
        // awaited itself, for the reason given there.
        void entry.then(() => {
            pending.delete(entry);
        });
    };
    return {
        register: track,
        admit: () => {
            if (closing)
                return undefined;
            let release;
            // The executor runs synchronously, so `release` is assigned before
            // `track` — and before this returns.
            track(new Promise((resolve) => {
                release = () => resolve();
            }));
            // Resolving twice is resolving once, so a handler whose `finally`
            // and whose error path both release does not free a sibling.
            return release;
        },
        get closing() {
            return closing;
        },
        drain: () => {
            if (draining !== undefined)
                return draining;
            closing = true;
            draining = (async () => {
                // Take a batch, wait for it, forget it, and go again while
                // anything new has arrived: see the file header for why one
                // snapshot is not enough.
                //
                // The drain removes what it awaited rather than leaving that to
                // `track`, so that it terminates on its own terms. A loop that
                // re-reads a set nothing removes from would spin on the
                // microtask queue for ever without ever yielding to a timer —
                // a shutdown that hangs rather than fails, which is the worse
                // of the two and the harder one to diagnose.
                for (let batch = [...pending]; batch.length > 0; batch = [...pending]) {
                    await Promise.all(batch);
                    for (const entry of batch)
                        pending.delete(entry);
                }
            })();
            return draining;
        },
    };
}
