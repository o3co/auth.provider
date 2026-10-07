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
import { loggableError } from "../logging/loggableError.mjs";
export function startSessionLifecycleSweeper(lifecycle, intervalMs, logger) {
    let sweeping;
    const sweep = async () => {
        try {
            const report = await lifecycle.resumePending();
            if (report.pending > 0 || report.unavailable > 0) {
                logger.warn({ ...report }, "session_lifecycle_sweep_pending");
            }
        }
        catch (error) {
            logger.error({ err: loggableError(error) }, "session_lifecycle_sweep_failed");
        }
    };
    const timer = setInterval(() => {
        if (sweeping !== undefined)
            return;
        sweeping = sweep().finally(() => {
            sweeping = undefined;
        });
    }, intervalMs);
    timer.unref?.();
    return {
        async stop() {
            clearInterval(timer);
            await sweeping;
        },
    };
}
