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

/*
 * Graceful shutdown for the scaffolded server, kept in the template so that
 * "does SIGTERM wait for in-flight requests, and for how long?" is answerable
 * from the code you deploy. See the template README, "Shutdown guarantees".
 */

import type { Server } from "node:http";
import { type Logger, loggableError } from "@o3co/auth-provider-core";

/** Options for {@link installGracefulShutdown}. */
export interface GracefulShutdownOptions {
	readonly logger: Logger;
	/** Reverse-topological component cleanup — normally `handle.dispose()`. */
	readonly cleanup?: () => void | Promise<void>;
	/** How long in-flight requests get before connections are cut. Default 10s. */
	readonly drainTimeoutMs?: number;
	/**
	 * How long `cleanup` gets before the shutdown gives up on it. Defaults to
	 * `drainTimeoutMs`, so the worst-case shutdown is the two budgets in
	 * sequence — size both against the orchestrator's grace period, not one.
	 */
	readonly cleanupTimeoutMs?: number;
	/** Injected in tests; defaults to {@link deferExit}. */
	readonly exit?: (code: number) => void;
	/** Injected in tests; defaults to `process.on`. */
	readonly onSignal?: (signal: NodeJS.Signals, handler: () => void) => void;
	/** Injected in tests; defaults to `process.removeListener`. */
	readonly offSignal?: (signal: NodeJS.Signals, handler: () => void) => void;
}

/**
 * Exit after yielding the loop once.
 *
 * The scaffolded app logs NDJSON through pino, whose default destination is not
 * synchronous, so calling `process.exit` in the same tick as the last
 * `logger.error` can drop exactly the lines that say why the shutdown failed.
 * One turn is a flush window, not a guarantee: a deployment that needs
 * certainty should pass an `exit` that flushes its own transport first.
 */
export function deferExit(code: number, exitProcess: (code: number) => void = process.exit): void {
	setImmediate(() => exitProcess(code));
}

const DEFAULT_DRAIN_TIMEOUT_MS = 10_000;
const SIGNALS: readonly NodeJS.Signals[] = ["SIGTERM", "SIGINT"];

/**
 * The least cleanup allowance federation grants get: 45 seconds. The
 * package's background registry drains on dispose, waiting for a rotated
 * upstream credential's write, and one refresh's longest tail is the upstream
 * hard timeout, the persist budget and the wait for the grant's lock, back to
 * back. With the shipped budgets (25 s + 3 s + 5 s) and
 * {@link FEDERATION_GRANTS_CLEANUP_MARGIN_MS} that is exactly this floor; a
 * raised budget raises the allowance ({@link cleanupAllowanceFor}). The
 * ten-second drain cleanup would otherwise inherit is shorter than the tail,
 * and would abandon exactly that write after the IdP had moved on to the new
 * refresh token. A host policy, not a grant setting: it bounds
 * `handle.dispose()`.
 */
export const FEDERATION_GRANTS_CLEANUP_ALLOWANCE_MS = 45_000;

/** What the allowance adds to the longest refresh tail: an exit margin. */
export const FEDERATION_GRANTS_CLEANUP_MARGIN_MS = 12_000;

/**
 * The most a timer can be asked for: Node's `setTimeout` takes a 32-bit signed
 * delay, and a larger one fires after ~1 ms instead. A sum of budgets an
 * operator set high enough to reach it would otherwise turn the allowance
 * into no allowance at all.
 */
const MAX_TIMER_MS = 2_147_483_647;

/**
 * The `cleanupTimeoutMs` to hand {@link installGracefulShutdown}, from the
 * config: while the feature is on, the longer of the floor above and the
 * configured refresh tail plus the margin; while it is off, nothing (the
 * drain's own budget applies). A fragment to spread, so an absent allowance
 * is absent rather than `undefined`. A config that carries no budgets (one
 * built by hand, without `reference.conf`) gets the floor.
 */
export function cleanupAllowanceFor(config: {
	readonly federationGrants?:
		| {
				readonly enabled?: boolean | undefined;
				readonly upstreamHardTimeoutMs?: number | undefined;
				readonly persistRetryBudgetMs?: number | undefined;
				readonly lockWaitMs?: number | undefined;
		  }
		| undefined;
}): { readonly cleanupTimeoutMs: number } | Record<string, never> {
	const grants = config.federationGrants;
	if (grants?.enabled !== true) return {};
	const budgets = [grants.upstreamHardTimeoutMs, grants.persistRetryBudgetMs, grants.lockWaitMs];
	const tail = budgets.every((budget) => typeof budget === "number" && Number.isFinite(budget))
		? (budgets as number[]).reduce(
				(sum, budget) => sum + budget,
				FEDERATION_GRANTS_CLEANUP_MARGIN_MS,
			)
		: 0;
	return {
		cleanupTimeoutMs: Math.min(
			Math.max(FEDERATION_GRANTS_CLEANUP_ALLOWANCE_MS, tail),
			MAX_TIMER_MS,
		),
	};
}

/**
 * Install the graceful shutdown on `server`. The guarantees (a deadline on the
 * drain, a non-zero exit past it, a bounded `cleanup` that never wedges the
 * process), the log line of each stage and how to size `drainTimeoutMs` plus
 * `cleanupTimeoutMs` below the orchestrator's kill grace period are in the
 * template README, "Shutdown guarantees". Beyond them: a `close` that fails is
 * not reported as a clean drain, and exits non-zero.
 */
export function installGracefulShutdown(server: Server, options: GracefulShutdownOptions): void {
	const {
		logger,
		cleanup,
		drainTimeoutMs = DEFAULT_DRAIN_TIMEOUT_MS,
		exit = deferExit,
		onSignal = (signal, handler): void => {
			process.on(signal, handler);
		},
		offSignal = (signal, handler): void => {
			process.removeListener(signal, handler);
		},
	} = options;

	const cleanupTimeoutMs = options.cleanupTimeoutMs ?? drainTimeoutMs;

	let shuttingDown = false;
	let finished = false;

	/** Sentinel so a timed-out cleanup is reported as that, not as a throw. */
	const CLEANUP_TIMED_OUT = Symbol("cleanup-timed-out");

	/**
	 * Await `cleanup`, but not forever. `cleanup()` is invoked inside the async
	 * wrapper so a synchronous throw lands in the same rejection path as an
	 * async one.
	 */
	const runCleanup = async (): Promise<typeof CLEANUP_TIMED_OUT | undefined> => {
		if (!cleanup) return;
		let timer: ReturnType<typeof setTimeout> | undefined;
		try {
			return await Promise.race([
				(async (): Promise<undefined> => {
					await cleanup();
					return undefined;
				})(),
				new Promise<typeof CLEANUP_TIMED_OUT>((resolve) => {
					timer = setTimeout(() => resolve(CLEANUP_TIMED_OUT), cleanupTimeoutMs);
					timer.unref?.();
				}),
			]);
		} finally {
			if (timer) clearTimeout(timer);
		}
	};

	/** Run `cleanup` and exit. Called by whichever of drain / deadline wins. */
	const finish = async (code: number, reason: string): Promise<void> => {
		if (finished) return;
		finished = true;
		let exitCode = code;
		// `reason` names whatever decided the exit code, so the line an operator
		// alerts on cannot say "drained" next to a non-zero code. The drain
		// outcome keeps its own key rather than being overwritten — both facts
		// are wanted, and a stable shape is what makes the line queryable.
		let outcome = reason;
		try {
			if ((await runCleanup()) === CLEANUP_TIMED_OUT) {
				logger.error({ cleanupTimeoutMs }, "shutdown_cleanup_timed_out");
				exitCode = 1;
				outcome = "cleanup-timeout";
			}
		} catch (err) {
			// Through the app logger, not `console.error`: a shutdown that
			// failed to release its Redis connections is exactly the line an
			// operator needs to find later, and a bare write is the one their
			// pipeline drops. The projection, not the error: `dispose()`
			// rejects with every cleanup's own error on `errors`, a store's
			// write — and what it wrote — among them.
			logger.error({ err: loggableError(err) }, "shutdown_cleanup_failed");
			exitCode = 1;
			outcome = "cleanup-failed";
		}
		logger.info({ reason: outcome, drain: reason, exitCode }, "shutdown_complete");
		exit(exitCode);
	};

	const handler = (): void => {
		if (shuttingDown) return;
		shuttingDown = true;
		for (const signal of SIGNALS) offSignal(signal, handler);
		logger.info({ drainTimeoutMs }, "shutdown_draining");

		const deadline = setTimeout(() => {
			logger.error({ drainTimeoutMs }, "shutdown_drain_deadline_exceeded");
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
				logger.error({ err: loggableError(err) }, "shutdown_server_close_failed");
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

	for (const signal of SIGNALS) onSignal(signal, handler);
}
