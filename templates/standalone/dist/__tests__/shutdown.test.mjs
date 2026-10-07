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
import { describe, expect, it, vi } from "vitest";
import { installGracefulShutdown } from "../shutdown.mjs";
/** A `Server` double whose `close` callback fires only when we say so. */
function makeServer() {
    let closeCallback;
    const server = {
        close: vi.fn((cb) => {
            closeCallback = cb;
            return server;
        }),
        closeIdleConnections: vi.fn(),
        closeAllConnections: vi.fn(),
    };
    return {
        server: server,
        spies: server,
        /** Simulate the last in-flight request finishing. */
        finishDraining: () => closeCallback?.(),
        /** Simulate `close` reporting a failure through its callback. */
        failClose: (err) => closeCallback?.(err),
        get drained() {
            return closeCallback !== undefined;
        },
    };
}
/**
 * A `Logger`-shaped spy. Typed rather than cast: `as never` would hide a real
 * mismatch the day the port gains a method, which is the whole reason the
 * shutdown path logs through the app logger instead of `console`.
 */
const makeLogger = () => {
    const spy = {
        trace: vi.fn(),
        debug: vi.fn(),
        info: vi.fn(),
        warn: vi.fn(),
        error: vi.fn(),
        fatal: vi.fn(),
        // `child` returns a Logger; returning this one keeps a child's calls
        // visible on the same spies, which is what a test wants.
        child: vi.fn(() => spy),
    };
    return spy;
};
/** Drive one shutdown without touching the real `process` or exiting. */
function install(opts = {}) {
    const { server, spies, finishDraining, failClose } = makeServer();
    const logger = makeLogger();
    const exit = vi.fn();
    const signals = new Map();
    installGracefulShutdown(server, {
        logger,
        cleanup: opts.cleanup ?? (() => { }),
        ...(opts.drainTimeoutMs === undefined ? {} : { drainTimeoutMs: opts.drainTimeoutMs }),
        exit,
        onSignal: (name, handler) => signals.set(name, handler),
        offSignal: (name) => signals.delete(name),
    });
    return { spies, logger, exit, signals, finishDraining, failClose };
}
describe("installGracefulShutdown (#290)", () => {
    it("listens for both SIGTERM and SIGINT", async () => {
        const { signals } = install();
        expect([...signals.keys()].sort()).toEqual(["SIGINT", "SIGTERM"]);
    });
    it("stops accepting connections and releases idle keep-alive sockets", async () => {
        const { spies, signals } = install();
        signals.get("SIGTERM")?.();
        expect(spies.close).toHaveBeenCalled();
        // Idle keep-alive sockets hold the server open with no request behind
        // them; releasing them is what lets a quiet server exit promptly.
        expect(spies.closeIdleConnections).toHaveBeenCalled();
    });
    it("runs cleanup once draining completes, then exits zero", async () => {
        const cleanup = vi.fn();
        const { exit, signals, finishDraining } = install({ cleanup });
        signals.get("SIGTERM")?.();
        expect(cleanup).not.toHaveBeenCalled();
        finishDraining();
        await vi.waitFor(() => expect(exit).toHaveBeenCalledWith(0));
        expect(cleanup).toHaveBeenCalledTimes(1);
    });
    it("ignores a second signal instead of running cleanup twice", async () => {
        // An operator pressing ^C twice, or a SIGINT arriving after SIGTERM,
        // must not start a second dispose over the first one's stores.
        const cleanup = vi.fn();
        const { signals, finishDraining, exit } = install({ cleanup });
        signals.get("SIGTERM")?.();
        signals.get("SIGINT")?.();
        finishDraining();
        await vi.waitFor(() => expect(exit).toHaveBeenCalled());
        expect(cleanup).toHaveBeenCalledTimes(1);
    });
    // The gap the audit was pointing at.
    it("forces the remaining connections closed when draining outruns the deadline", async () => {
        vi.useFakeTimers();
        try {
            const { spies, signals, exit } = install({ drainTimeoutMs: 5_000 });
            signals.get("SIGTERM")?.();
            expect(spies.closeAllConnections).not.toHaveBeenCalled();
            await vi.advanceTimersByTimeAsync(5_000);
            expect(spies.closeAllConnections).toHaveBeenCalled();
            expect(exit).toHaveBeenCalled();
        }
        finally {
            vi.useRealTimers();
        }
    });
    it("exits non-zero on a forced close, so the drain outcome is visible", async () => {
        // An orchestrator that only ever sees exit 0 cannot tell a clean drain
        // from one that ran out of time and cut requests off.
        vi.useFakeTimers();
        try {
            const { signals, exit, logger } = install({ drainTimeoutMs: 5_000 });
            signals.get("SIGTERM")?.();
            await vi.advanceTimersByTimeAsync(5_000);
            expect(exit).toHaveBeenCalledWith(1);
            expect(logger.error).toHaveBeenCalled();
        }
        finally {
            vi.useRealTimers();
        }
    });
    it("does not force-close a drain that finished in time", async () => {
        vi.useFakeTimers();
        try {
            const { spies, signals, finishDraining, exit } = install({ drainTimeoutMs: 5_000 });
            signals.get("SIGTERM")?.();
            finishDraining();
            await vi.waitFor(() => expect(exit).toHaveBeenCalledWith(0));
            await vi.advanceTimersByTimeAsync(10_000);
            expect(spies.closeAllConnections).not.toHaveBeenCalled();
            expect(exit).toHaveBeenCalledTimes(1);
        }
        finally {
            vi.useRealTimers();
        }
    });
    it("reports a cleanup failure through the app logger, not console", async () => {
        // Every other line this service emits is NDJSON through pino; a bare
        // console.error on the shutdown path is the one a log pipeline drops.
        const { logger, exit, signals, finishDraining } = install({
            cleanup: () => {
                throw new Error("redis quit failed");
            },
        });
        signals.get("SIGTERM")?.();
        finishDraining();
        await vi.waitFor(() => expect(exit).toHaveBeenCalled());
        expect(logger.error).toHaveBeenCalledWith(expect.objectContaining({ err: expect.any(Error) }), expect.stringContaining("cleanup"));
    });
    it("still exits when cleanup throws — a failed dispose must not wedge the process", async () => {
        const { exit, signals, finishDraining } = install({
            cleanup: async () => {
                throw new Error("dispose failed");
            },
        });
        signals.get("SIGTERM")?.();
        finishDraining();
        await vi.waitFor(() => expect(exit).toHaveBeenCalledWith(1));
    });
    it("does not report a failed close as a clean drain", async () => {
        // `server.close` reports through its callback -- "Server is not running"
        // is the common one, but any listener teardown failure lands there.
        // Exiting 0 on it would tell an orchestrator the listener came down
        // when it did not.
        const { exit, logger, signals, failClose } = install();
        signals.get("SIGTERM")?.();
        failClose(new Error("Server is not running"));
        await vi.waitFor(() => expect(exit).toHaveBeenCalledWith(1));
        expect(logger.error).toHaveBeenCalledWith(expect.objectContaining({ err: expect.any(Error) }), expect.stringContaining("close"));
    });
    it("still runs cleanup when close reports a failure", async () => {
        // The listener failing to come down is no reason to leak the Redis
        // connections behind it.
        const cleanup = vi.fn();
        const { exit, signals, failClose } = install({ cleanup });
        signals.get("SIGTERM")?.();
        failClose(new Error("teardown failed"));
        await vi.waitFor(() => expect(exit).toHaveBeenCalled());
        expect(cleanup).toHaveBeenCalledTimes(1);
    });
    it("removes its own signal listeners once shutting down", async () => {
        // Otherwise a repeated signal keeps re-entering a handler that has
        // already handed the process over to `close`.
        const { signals } = install();
        signals.get("SIGTERM")?.();
        expect(signals.size).toBe(0);
    });
});
