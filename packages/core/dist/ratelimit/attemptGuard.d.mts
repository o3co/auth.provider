import type { Request, RequestHandler, Response } from "express";
import type { AuditSink } from "../audit/types.mjs";
import type { DeploymentMode } from "../deployment/types.mjs";
import { type ErrorEnvelope } from "../errors/envelope.mjs";
import type { Logger } from "../logging/Logger.mjs";
import { type AttemptCount, type AttemptCounter, type AttemptSpec } from "./attempts.mjs";
/** How long a consume is waited for by default before the guard answers `503`. */
export declare const DEFAULT_ATTEMPT_COUNTER_TIMEOUT_MS = 2000;
export interface AttemptGuardOptions {
    /** The `attemptCounter` slot's value. Absent: a per-process counter, where the deployment mode allows one. */
    readonly counter?: AttemptCounter;
    /** The `deploymentMode` slot's value. */
    readonly deploymentMode: DeploymentMode;
    /** The key prefix (`<tag>:<id>`) and the `tag` on the guard's log and audit emissions. No `:`. */
    readonly tag: string;
    /** The owning module's limit, read once here: every key under `tag` is counted against it. */
    readonly spec: AttemptSpec;
    /** Defaults to `consoleLogger`. */
    readonly logger?: Logger;
    /** When present, an outage is also audited as `rate_limit.unavailable`. */
    readonly auditSink?: AuditSink;
    /** How long a consume is waited for. Default {@link DEFAULT_ATTEMPT_COUNTER_TIMEOUT_MS}. */
    readonly timeoutMs?: number;
    /** The 429's error code and description. Default `rate_limited`, "Rate limit exceeded". */
    readonly refused?: {
        readonly error: string;
        readonly description: string;
    };
    /** Epoch milliseconds, for reading a count and for the per-process counter. Default `Date.now`. */
    readonly now?: () => number;
    /** The per-process counter's `maxEntries`; a shared counter is sized by its own backend. */
    readonly maxEntries?: number;
}
export interface AttemptPerIpOptions {
    /**
     * Called after a refusal is answered, so the owning module can audit it.
     * A throw or a rejection is logged `attempt_refused_hook_failed` and changes nothing.
     */
    readonly onRefused?: (req: Request, count: AttemptCount) => unknown;
}
/** What the guard answered an attempt with. Only on `allowed` does the caller go on; the others are already answered. */
export type AttemptVerdict = {
    readonly verdict: "allowed";
    readonly count: AttemptCount;
} | {
    readonly verdict: "refused";
    readonly count: AttemptCount;
} | {
    readonly verdict: "unavailable";
};
export interface AttemptGuard {
    /** Counts one attempt under `<tag>:<id>`, and answers the request itself unless it is allowed. */
    attempt(req: Request, res: Response, id: string): Promise<AttemptVerdict>;
    /** Middleware counting one attempt per request under `<tag>:ip:<req.ip>`. */
    perIp(options?: AttemptPerIpOptions): RequestHandler;
}
/** Why a counter had no usable answer. */
export type AttemptCounterFailure = "threw" | "timed_out" | "malformed";
/** The 503 body of an attempt counter outage. */
export declare const attemptCounterUnavailableEnvelope: () => ErrorEnvelope;
export declare function createAttemptGuard(options: AttemptGuardOptions): AttemptGuard;
//# sourceMappingURL=attemptGuard.d.mts.map