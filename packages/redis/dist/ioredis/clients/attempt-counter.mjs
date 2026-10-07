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
import { runScript } from "../commands.mjs";
import { redisDurability } from "../durability.mjs";
import { ATTEMPT_COUNTER_CONSUME } from "../scripts/attempt-counter.mjs";
export function makeIoredisAttemptCounterClient(io, options = {}) {
    return {
        async consume(key, input) {
            const reply = await runScript(io, ATTEMPT_COUNTER_CONSUME, [key], [
                String(input.nowMs),
                String(input.limit),
                String(input.resetAtMs),
                String(input.expiryAllowanceMs),
            ]);
            if (!Array.isArray(reply) || reply.length !== 3) {
                throw new Error("attemptCounterClient.consume: unexpected reply from the consume script");
            }
            const [allowed, count, resetAtMs] = reply;
            if ((allowed !== 0 && allowed !== 1) ||
                typeof count !== "number" ||
                typeof resetAtMs !== "number") {
                throw new Error("attemptCounterClient.consume: unexpected reply from the consume script");
            }
            return { allowed: allowed === 1, count, resetAtMs };
        },
        durability: () => redisDurability(io, options),
    };
}
