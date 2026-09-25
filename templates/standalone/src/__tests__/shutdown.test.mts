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

import { createServer, type Server } from "node:http";
import {
	type BootstrapMap,
	createApp,
	createMemoryReplaySeenSet,
	defineModule,
	type Logger,
} from "@o3co/auth-provider-core";
import { makeValidCoreConfig } from "@o3co/auth-provider-core/testing";
import { describe, expect, it, vi } from "vitest";
import {
	cleanupAllowanceFor,
	deferExit,
	FEDERATION_GRANTS_CLEANUP_ALLOWANCE_MS,
	FEDERATION_GRANTS_CLEANUP_MARGIN_MS,
	installGracefulShutdown,
} from "../shutdown.mjs";

/** A `Server` double whose `close` callback fires only when we say so. */
function makeServer() {
	let closeCallback: ((err?: Error) => void) | undefined;
	const server = {
		close: vi.fn((cb?: (err?: Error) => void) => {
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
		/** Simulate `close` reporting a failure through its callback. */
		failClose: (err: Error) => closeCallback?.(err),
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
		child: vi.fn(() => spy as unknown as Logger),
	};
	return spy satisfies Logger;
};

/**
 * A logger that serialises every own property of what it is handed, `cause`
 * and non-enumerable fields included — a deployment is free to install one.
 * `lines` is what it wrote; its levels are spies.
 */
const serialiseEverythingLogger = () => {
	const lines: string[] = [];
	const walk = (value: unknown, seen = new WeakSet<object>()): unknown => {
		if (typeof value !== "object" || value === null) return value;
		if (seen.has(value)) return "[circular]";
		seen.add(value);
		const out: Record<string, unknown> = {};
		for (const key of Object.getOwnPropertyNames(value)) {
			out[key] = walk((value as Record<string, unknown>)[key], seen);
		}
		return out;
	};
	const record = (level: string) =>
		vi.fn((...args: unknown[]): void => {
			lines.push(JSON.stringify({ level, args: walk(args) }));
		});
	const logger = {
		trace: record("trace"),
		debug: record("debug"),
		info: record("info"),
		warn: record("warn"),
		error: record("error"),
		fatal: record("fatal"),
		child: vi.fn(() => logger as unknown as Logger),
	};
	return { logger: logger satisfies Logger, lines };
};

/** A logged projection's `stack`: frames only, from the first. */
const FRAMES = expect.stringMatching(/^ {4}at /);

/** Drive one shutdown without touching the real `process` or exiting. */
function install(
	opts: {
		cleanup?: () => void | Promise<void>;
		drainTimeoutMs?: number;
		cleanupTimeoutMs?: number;
		logger?: ReturnType<typeof makeLogger>;
	} = {},
) {
	const { server, spies, finishDraining, failClose } = makeServer();
	const logger = opts.logger ?? makeLogger();
	const exit = vi.fn();
	const signals = new Map<string, () => void>();

	installGracefulShutdown(server, {
		logger,
		cleanup: opts.cleanup ?? (() => {}),
		...(opts.drainTimeoutMs === undefined ? {} : { drainTimeoutMs: opts.drainTimeoutMs }),
		...(opts.cleanupTimeoutMs === undefined ? {} : { cleanupTimeoutMs: opts.cleanupTimeoutMs }),
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
			// Each stage is an event: object-first, a snake_case name.
			expect(logger.info).toHaveBeenCalledWith({ drainTimeoutMs: 5_000 }, "shutdown_draining");
			expect(logger.error).toHaveBeenCalledWith(
				{ drainTimeoutMs: 5_000 },
				"shutdown_drain_deadline_exceeded",
			);
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

	it("reports a cleanup failure through the app logger, not console, as loggableError's projection", async () => {
		// Every other line this service emits is NDJSON through pino; a bare
		// console.error on the shutdown path is the one a log pipeline drops.
		// What a real `handle.dispose()` rejects with is an AggregateError of
		// every cleanup's own error. The line names each member and its code,
		// and carries nothing of what they hold: an OAuth library's refusal
		// keeps the refresh answer it refused on a non-Error cause, an ioredis
		// reply the write it refused.
		const refusedRefresh = Object.assign(
			new Error("invalid response encountered", {
				cause: { body: { refresh_token: "1//0g-UPSTREAM-S3CRET" } },
			}),
			{ name: "ClientError", code: "OAUTH_INVALID_RESPONSE" },
		);
		const refusedWrite = Object.assign(
			new Error("READONLY You can't write against a read only replica."),
			{
				name: "ReplyError",
				command: { name: "set", args: ["fg:credential:grant-1", "1//0g-ARGS-S3CRET"] },
			},
		);
		const failingCleanups = defineModule({
			name: "test:failing-cleanups",
			provides: {
				replaySeenSet: () => createMemoryReplaySeenSet(),
				challengeStore: () => ({}) as never,
			},
			lifecycle: {
				replaySeenSet: {
					eager: true,
					cleanup: () => {
						throw refusedRefresh;
					},
				},
				challengeStore: {
					eager: true,
					cleanup: () => {
						throw refusedWrite;
					},
				},
			},
		});
		const handle = await createApp({
			modules: [failingCleanups],
			bootstrapComponents: {
				config: makeValidCoreConfig(),
				pathResolver: (path: string) => path,
			} as unknown as BootstrapMap,
		});
		const { logger, lines } = serialiseEverythingLogger();
		const { exit, signals, finishDraining } = install({
			logger,
			cleanup: () => handle.dispose(),
		});
		signals.get("SIGTERM")?.();
		finishDraining();
		await vi.waitFor(() => expect(exit).toHaveBeenCalled());
		expect(logger.error).toHaveBeenCalledWith(
			{
				err: {
					name: "AggregateError",
					detail: expect.stringMatching(/^AppHandle\.dispose: 2 cleanup errors /),
					stack: FRAMES,
					aggregateErrors: expect.arrayContaining([
						{
							name: "ClientError",
							detail: "invalid response encountered",
							code: "OAUTH_INVALID_RESPONSE",
							stack: FRAMES,
						},
						{
							name: "ReplyError",
							detail: "READONLY You can't write against a read only replica.",
							command: { name: "set" },
							stack: FRAMES,
						},
					]),
				},
			},
			"shutdown_cleanup_failed",
		);
		for (const line of lines) {
			expect(line).not.toContain("S3CRET");
			expect(line).not.toContain("refresh_token");
		}
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

	it("does not report a failed close as a clean drain, and logs the failure as loggableError's projection", async () => {
		// `server.close` reports through its callback -- "Server is not running"
		// is the common one, but any listener teardown failure lands there.
		// Exiting 0 on it would tell an orchestrator the listener came down
		// when it did not. A real server that is not listening gives Node's
		// own error; the line keeps its name, message, code and frames.
		const server = createServer();
		const { logger, lines } = serialiseEverythingLogger();
		const exit = vi.fn();
		const signals = new Map<string, () => void>();
		installGracefulShutdown(server, {
			logger,
			exit,
			onSignal: (name, handler) => signals.set(name, handler),
			offSignal: (name) => signals.delete(name),
		});
		signals.get("SIGTERM")?.();
		await vi.waitFor(() => expect(exit).toHaveBeenCalledWith(1));
		expect(logger.error).toHaveBeenCalledWith(
			{
				err: {
					name: "Error",
					detail: "Server is not running.",
					code: "ERR_SERVER_NOT_RUNNING",
					stack: FRAMES,
				},
			},
			"shutdown_server_close_failed",
		);
		// The frames, never the header line that repeats the message.
		for (const line of lines) expect(line).not.toContain("Error [ERR_SERVER_NOT_RUNNING]");
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

	it("bounds cleanup so a hanging dispose cannot wedge the process", async () => {
		// The guarantees above say cleanup "never wedges the process", but `finish`
		// awaited it with no deadline — and the drain deadline is already cleared
		// by then, so a dispose that never settles meant `exit` was never reached.
		// The same defect was found in auth.proxy#81 and auth.policy-verifier#210,
		// both of which took this file as their starting point.
		vi.useFakeTimers();
		try {
			const { signals, finishDraining, exit, logger } = install({
				cleanup: () => new Promise<void>(() => {}),
				drainTimeoutMs: 5_000,
			});
			signals.get("SIGTERM")?.();
			finishDraining();
			await vi.advanceTimersByTimeAsync(5_000);
			expect(logger.error).toHaveBeenCalledWith(
				{ cleanupTimeoutMs: 5_000 },
				"shutdown_cleanup_timed_out",
			);
			expect(exit).toHaveBeenCalledWith(1);
		} finally {
			vi.useRealTimers();
		}
	});

	it("does not penalise a cleanup that finishes inside its budget", async () => {
		vi.useFakeTimers();
		try {
			const { signals, finishDraining, exit } = install({
				cleanup: () => Promise.resolve(),
				drainTimeoutMs: 5_000,
			});
			signals.get("SIGTERM")?.();
			finishDraining();
			await vi.advanceTimersByTimeAsync(10_000);
			expect(exit).toHaveBeenCalledExactlyOnceWith(0);
		} finally {
			vi.useRealTimers();
		}
	});

	it("defers the real exit a turn so a buffered log destination can flush", async () => {
		// The scaffolded app logs NDJSON through pino, whose default destination is
		// not synchronous: exiting in the same tick as the last `logger.error` can
		// drop exactly the `cleanup failed` line an operator would look for.
		const exitProcess = vi.fn();
		deferExit(3, exitProcess);
		expect(exitProcess).not.toHaveBeenCalled();
		await new Promise((resolve) => setImmediate(resolve));
		expect(exitProcess).toHaveBeenCalledWith(3);
	});

	it("reports the cleanup outcome as the reason, not the drain that preceded it", async () => {
		// `exitCode` became 1 while `reason` still said "drained", so the one line
		// an operator alerts on contradicted itself. The drain outcome is still
		// carried, under its own key, so neither fact is lost.
		const { signals, finishDraining, logger, exit } = install({
			cleanup: () => Promise.reject(new Error("teardown failed")),
		});
		signals.get("SIGTERM")?.();
		finishDraining();
		await new Promise((resolve) => setImmediate(resolve));
		expect(logger.info).toHaveBeenCalledWith(
			{ reason: "cleanup-failed", drain: "drained", exitCode: 1 },
			"shutdown_complete",
		);
		expect(exit).toHaveBeenCalledWith(1);
	});

	it("keeps reason and drain identical when cleanup succeeds", async () => {
		const { signals, finishDraining, logger } = install({ cleanup: () => Promise.resolve() });
		signals.get("SIGTERM")?.();
		finishDraining();
		await new Promise((resolve) => setImmediate(resolve));
		expect(logger.info).toHaveBeenCalledWith(
			{ reason: "drained", drain: "drained", exitCode: 0 },
			"shutdown_complete",
		);
	});

	it("removes its own signal listeners once shutting down", async () => {
		// Otherwise a repeated signal keeps re-entering a handler that has
		// already handed the process over to `close`.
		const { signals } = install();
		signals.get("SIGTERM")?.();
		expect(signals.size).toBe(0);
	});
});

describe("#593 slice 7: the cleanup allowance federation grants need", () => {
	it("is at least the 45 seconds the package asks for, and only when the feature is on", () => {
		// The package's drain waits for a rotated credential's write; the
		// default cleanup budget is the ten-second drain, which is shorter than
		// the upstream hard timeout and persist budget the feature ships with —
		// a shutdown under it abandons exactly the write the drain exists for.
		expect(FEDERATION_GRANTS_CLEANUP_ALLOWANCE_MS).toBeGreaterThanOrEqual(45_000);
		expect(cleanupAllowanceFor({ federationGrants: { enabled: true } })).toEqual({
			cleanupTimeoutMs: FEDERATION_GRANTS_CLEANUP_ALLOWANCE_MS,
		});
		// Off, nothing: the cleanup budget stays the drain's, as it was.
		expect(cleanupAllowanceFor({ federationGrants: { enabled: false } })).toEqual({});
		expect(cleanupAllowanceFor({})).toEqual({});
	});

	it("grows with the configured refresh tail, so a raised budget is not cut off by a fixed timer (Copilot, #614)", () => {
		// The longest tail one refresh has: the upstream hard timeout, the
		// persist budget and the wait for the lock, back to back, plus an exit
		// margin. The shipped budgets (25 s + 3 s + 5 s) land exactly on the
		// floor; a deployment that doubles its upstream timeout gets more.
		const shipped = {
			upstreamHardTimeoutMs: 25_000,
			persistRetryBudgetMs: 3_000,
			lockWaitMs: 5_000,
		};
		expect(
			25_000 + 3_000 + 5_000 + FEDERATION_GRANTS_CLEANUP_MARGIN_MS,
			"the margin is what makes the shipped budgets the floor",
		).toBe(FEDERATION_GRANTS_CLEANUP_ALLOWANCE_MS);
		expect(cleanupAllowanceFor({ federationGrants: { enabled: true, ...shipped } })).toEqual({
			cleanupTimeoutMs: FEDERATION_GRANTS_CLEANUP_ALLOWANCE_MS,
		});
		expect(
			cleanupAllowanceFor({
				federationGrants: { enabled: true, ...shipped, upstreamHardTimeoutMs: 60_000 },
			}),
		).toEqual({ cleanupTimeoutMs: 60_000 + 3_000 + 5_000 + FEDERATION_GRANTS_CLEANUP_MARGIN_MS });
		// Lowered budgets never go below the documented minimum, and a config
		// without budgets (built by hand) gets the floor rather than a guess.
		expect(
			cleanupAllowanceFor({
				federationGrants: { enabled: true, ...shipped, upstreamHardTimeoutMs: 1_000 },
			}),
		).toEqual({ cleanupTimeoutMs: FEDERATION_GRANTS_CLEANUP_ALLOWANCE_MS });
		expect(
			cleanupAllowanceFor({ federationGrants: { enabled: true, upstreamHardTimeoutMs: 90_000 } }),
		).toEqual({ cleanupTimeoutMs: FEDERATION_GRANTS_CLEANUP_ALLOWANCE_MS });
	});

	it("never asks a timer for more than Node can count: an oversized sum is capped, not overflowed (Copilot, #614)", () => {
		// setTimeout takes a 32-bit signed delay; past it the timer fires after
		// about a millisecond, which would turn a generous allowance into none.
		const oversized = cleanupAllowanceFor({
			federationGrants: {
				enabled: true,
				upstreamHardTimeoutMs: 2_000_000_000,
				persistRetryBudgetMs: 2_000_000_000,
				lockWaitMs: 5_000,
			},
		});
		expect(oversized).toEqual({ cleanupTimeoutMs: 2_147_483_647 });
	});

	it("is honoured by the shutdown: a cleanup that needs longer than the drain is given it", async () => {
		vi.useFakeTimers();
		try {
			const { signals, finishDraining, exit } = install({
				cleanup: () => new Promise<void>((resolve) => setTimeout(resolve, 30_000)),
				drainTimeoutMs: 5_000,
				...cleanupAllowanceFor({ federationGrants: { enabled: true } }),
			});
			signals.get("SIGTERM")?.();
			finishDraining();
			await vi.advanceTimersByTimeAsync(31_000);
			expect(exit).toHaveBeenCalledExactlyOnceWith(0);
		} finally {
			vi.useRealTimers();
		}
	});
});
