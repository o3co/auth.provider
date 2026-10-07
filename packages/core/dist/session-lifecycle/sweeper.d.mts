/**
 * The periodic sweep that resumes pending closes: one sweep at a time, a
 * failed one logged and the next run at the next interval. Its timer never
 * keeps the process alive, and `stop` waits for the sweep in flight.
 */
import type { EventLogger } from "../logging/Logger.mjs";
import type { SessionLifecycle } from "./service.mjs";
export interface SessionLifecycleSweeper {
    /** Stops sweeping, and resolves once the sweep in flight, if any, has settled. */
    stop(): Promise<void>;
}
export declare function startSessionLifecycleSweeper(lifecycle: Pick<SessionLifecycle, "resumePending">, intervalMs: number, logger: EventLogger): SessionLifecycleSweeper;
//# sourceMappingURL=sweeper.d.mts.map