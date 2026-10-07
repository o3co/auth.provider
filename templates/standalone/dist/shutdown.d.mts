import type { Server } from "node:http";
import type { Logger } from "@o3co/auth-provider-core";
/**
 * Graceful shutdown for the scaffolded server (#290).
 *
 * ## Why this is in the template rather than a dependency
 *
 * It used to be `gracefulShutdown` from `@o3co/auth.utils@0.0.4`. The ops
 * review's objection was not that the package is bad — it is that for the
 * component which terminates every user session, "does SIGTERM wait for
 * in-flight requests, and for how long?" has to be answerable from the code an
 * operator deploys, and it was answerable only by reading a pre-1.0 package
 * with no contract pinned here.
 *
 * Reading it answered the question, and the answer was the reason to move it:
 * **there was no deadline**. `server.close()` waits for in-flight requests
 * indefinitely, so a single stuck request meant the process never exited on
 * its own and the orchestrator's SIGKILL took it down mid-flight — the
 * opposite of a graceful shutdown, arriving only under the load that produces
 * a stuck request. The cleanup-failure path also wrote to `console.error`, one
 * bare line in a service whose every other line is NDJSON.
 *
 * Neither is fixed by documenting or pinning the dependency, which is why this
 * is ~40 lines here with tests, rather than a version range and a README
 * paragraph.
 *
 * ## The guarantees, stated
 *
 * 1. **SIGTERM and SIGINT** both start it; the second signal is ignored rather
 *    than starting a second dispose over the first one's stores.
 * 2. **New connections stop immediately** (`server.close`), and idle keep-alive
 *    sockets are released (`closeIdleConnections`) — they hold the server open
 *    with no request behind them, so a quiet server would otherwise wait out
 *    the whole deadline for nothing.
 * 3. **In-flight requests are given `drainTimeoutMs`** (default 10s) to finish.
 * 4. **Past the deadline, remaining connections are cut** (`closeAllConnections`)
 *    and the process exits **non-zero** — an orchestrator that only ever sees
 *    `0` cannot tell a clean drain from one that ran out of time.
 * 5. **`cleanup` runs after draining, before exit**, and its failure is logged
 *    through the app logger and reflected in the exit code. It never wedges the
 *    process: a dispose that throws still exits.
 * 6. **A `close` that fails is not reported as a clean drain.** `server.close`
 *    reports through its callback, and treating that as success would tell an
 *    orchestrator the listener came down when it did not.
 *
 * Size `drainTimeoutMs` **below** the orchestrator's own kill grace period
 * (Kubernetes `terminationGracePeriodSeconds`, compose `stop_grace_period`,
 * both 30s by default) — the point is to close on our terms before SIGKILL
 * arrives on someone else's.
 */
export interface GracefulShutdownOptions {
    readonly logger: Logger;
    /** Reverse-topological component cleanup — normally `handle.dispose()`. */
    readonly cleanup?: () => void | Promise<void>;
    /** How long in-flight requests get before connections are cut. Default 10s. */
    readonly drainTimeoutMs?: number;
    /** Injected in tests; defaults to `process.exit`. */
    readonly exit?: (code: number) => void;
    /** Injected in tests; defaults to `process.on`. */
    readonly onSignal?: (signal: NodeJS.Signals, handler: () => void) => void;
    /** Injected in tests; defaults to `process.removeListener`. */
    readonly offSignal?: (signal: NodeJS.Signals, handler: () => void) => void;
}
export declare function installGracefulShutdown(server: Server, options: GracefulShutdownOptions): void;
//# sourceMappingURL=shutdown.d.mts.map