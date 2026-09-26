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
import { randomUUID } from "node:crypto";
const DEFAULT_TTL_MS = 5_000;
const DEFAULT_WAIT_MS = 4_000;
const POLL_INTERVAL_MS = 50;
/**
 * Redis-backed advisory lock. Uses SET NX PX for acquire and compare-and-delete
 * for release — the release path fetches the current value and only issues DEL
 * when the value still matches the caller's acquire token, so a TTL-expired
 * caller cannot evict a subsequent holder.
 *
 * The compare-and-delete is GET + DEL — not atomic. A small race window exists
 * between the two commands, during which another process could acquire the
 * lock after our GET; our DEL would then evict them one poll-cycle early. The
 * window is ms-sized and the consequence is bounded — consumers that need
 * strict atomicity should upgrade to a Lua EVAL-based release.
 *
 * Plan line 837: "Upgrading to a Lua script would remove the race but adds
 * dependency on EVAL being available (which it is on all mainstream redis
 * versions). Defer unless pattern is reused heavily."
 */
export function createRedisLock(opts) {
    const prefix = opts.keyPrefix ?? "ftlock:";
    const k = (sid, name) => `${prefix}${sid}:${name}`;
    return {
        async acquireLock(a) {
            const key = k(a.sid, a.federationName);
            const ttlMs = a.ttlMs ?? DEFAULT_TTL_MS;
            const waitForMs = a.waitForMs ?? DEFAULT_WAIT_MS;
            const deadline = Date.now() + waitForMs;
            const token = randomUUID();
            while (true) {
                const result = await opts.client.set(key, token, { PX: ttlMs, NX: true });
                if (result !== null) {
                    return {
                        acquired: true,
                        release: async () => {
                            // Compare-and-delete: only remove the entry when the stored
                            // value still matches our acquire token. Prevents evicting a
                            // subsequently acquired lock after our TTL expired under a
                            // slow operation.
                            const current = await opts.client.get(key);
                            if (current === token) {
                                await opts.client.del(key);
                            }
                        },
                    };
                }
                if (Date.now() >= deadline) {
                    return { acquired: false, reason: "timeout" };
                }
                await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS));
            }
        },
    };
}
