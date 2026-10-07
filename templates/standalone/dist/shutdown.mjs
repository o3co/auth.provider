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
const DEFAULT_DRAIN_TIMEOUT_MS = 10_000;
const SIGNALS = ["SIGTERM", "SIGINT"];
export function installGracefulShutdown(server, options) {
    const { logger, cleanup, drainTimeoutMs = DEFAULT_DRAIN_TIMEOUT_MS, exit = (code) => {
        process.exit(code);
    }, onSignal = (signal, handler) => {
        process.on(signal, handler);
    }, offSignal = (signal, handler) => {
        process.removeListener(signal, handler);
    }, } = options;
    let shuttingDown = false;
    let finished = false;
    /** Run `cleanup` and exit. Called by whichever of drain / deadline wins. */
    const finish = async (code, reason) => {
        if (finished)
            return;
        finished = true;
        let exitCode = code;
        try {
            await cleanup?.();
        }
        catch (err) {
            // Through the app logger, not `console.error`: a shutdown that
            // failed to release its Redis connections is exactly the line an
            // operator needs to find later, and a bare write is the one their
            // pipeline drops.
            logger.error({ err }, "graceful shutdown: cleanup failed");
            exitCode = 1;
        }
        logger.info({ reason, exitCode }, "graceful shutdown: complete");
        exit(exitCode);
    };
    const handler = () => {
        if (shuttingDown)
            return;
        shuttingDown = true;
        for (const signal of SIGNALS)
            offSignal(signal, handler);
        logger.info({ drainTimeoutMs }, "graceful shutdown: draining");
        const deadline = setTimeout(() => {
            logger.error({ drainTimeoutMs }, "graceful shutdown: drain deadline exceeded, closing remaining connections");
            server.closeAllConnections();
            void finish(1, "drain-timeout");
        }, drainTimeoutMs);
        // The deadline must not be what keeps the process alive once the drain
        // has already finished.
        deadline.unref?.();
        server.close((err) => {
            clearTimeout(deadline);
            if (err) {
                // `close` reports through its callback — "Server is not running"
                // is the common one, but any listener teardown failure lands
                // here. Reporting "drained" and exiting 0 on it would tell an
                // orchestrator the shutdown went cleanly when the listener did
                // not actually come down.
                logger.error({ err }, "graceful shutdown: server close failed");
                void finish(1, "close-failed");
                return;
            }
            void finish(0, "drained");
        });
        // Idle keep-alive sockets have no request behind them, so nothing is
        // lost by releasing them — and without this a quiet server waits out
        // the whole deadline for connections that will never send anything.
        server.closeIdleConnections();
    };
    for (const signal of SIGNALS)
        onSignal(signal, handler);
}
