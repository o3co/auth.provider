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
 * Issue #290 — shutdown was delegated to `@o3co/auth.utils@0.0.4`, whose
 * guarantees were not pinned by any contract this repository could check.
 *
 * Reading the 22 lines answered the question the issue asked, and the answer
 * was worth knowing: **there was no force-close deadline**. `server.close()`
 * waits for in-flight requests indefinitely, so one stuck request meant the
 * process never exited on its own and the orchestrator's SIGKILL took it down
 * mid-flight — the opposite of a graceful shutdown, and invisible until it
 * happened. The cleanup-failure path also wrote to `console.error`, a bare
 * line in a service whose every other line is NDJSON.
 *
 * So the behaviour lives here now, with a deadline and the app's own logger,
 * and these tests are the contract the issue said was missing.
 */

import type { Server } from "node:http";
import { describe, expect, it, vi } from "vitest";
import { installGracefulShutdown } from "../shutdown.mjs";

/** A `Server` double whose `close` callback fires only when we say so. */
function makeServer() {
	let closeCallback: (() => void) | undefined;
	const server = {
		close: vi.fn((cb?: () => void) => {
			closeCallback = cb;
			return server;
		}),
		closeIdleConnections: vi.fn(),
		closeAllConnections: vi.fn(),
	};
	return {
		server: server as unknown as Server,
		spies: server,
		/** Simulate the last in-flight request finishing. */
		finishDraining: () => closeCallback?.(),
		get drained() {
			return closeCallback !== undefined;
		},
	};
}

const makeLogger = () => ({
	info: vi.fn(),
	warn: vi.fn(),
	error: vi.fn(),
	debug: vi.fn(),
});

/** Drive one shutdown without touching the real `process` or exiting. */
function install(opts: { cleanup?: () => void | Promise<void>; drainTimeoutMs?: number } = {}) {
	const { server, spies, finishDraining } = makeServer();
	const logger = makeLogger();
	const exit = vi.fn();
	const signals = new Map<string, () => void>();

	installGracefulShutdown(server, {
		logger: logger as never,
		cleanup: opts.cleanup ?? (() => {}),
		...(opts.drainTimeoutMs === undefined ? {} : { drainTimeoutMs: opts.drainTimeoutMs }),
		exit,
		onSignal: (name, handler) => signals.set(name, handler),
		offSignal: (name) => signals.delete(name),
	});

	return { spies, logger, exit, signals, finishDraining };
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
		} finally {
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
		} finally {
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
		} finally {
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
		expect(logger.error).toHaveBeenCalledWith(
			expect.objectContaining({ err: expect.any(Error) }),
			expect.stringContaining("cleanup"),
		);
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

	it("removes its own signal listeners once shutting down", async () => {
		// Otherwise a repeated signal keeps re-entering a handler that has
		// already handed the process over to `close`.
		const { signals } = install();
		signals.get("SIGTERM")?.();
		expect(signals.size).toBe(0);
	});
});
