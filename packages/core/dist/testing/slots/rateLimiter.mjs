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
export function createTestRateLimiter(options = {}) {
    let checked = Object.freeze([]);
    let failure;
    const counts = new Map();
    const { limit } = options;
    return {
        kind: "test",
        ...(options.failMode === undefined ? {} : { failMode: options.failMode }),
        get checked() {
            return checked;
        },
        failWith(error) {
            failure = { error };
        },
        recover() {
            failure = undefined;
        },
        async check(key) {
            if (failure !== undefined)
                throw failure.error;
            checked = Object.freeze([...checked, key]);
            if (limit === undefined)
                return { allowed: true };
            const count = (counts.get(key) ?? 0) + 1;
            counts.set(key, count);
            return { allowed: count <= limit, remaining: Math.max(limit - count, 0), limit };
        },
    };
}
