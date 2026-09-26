import { type Logger, type ReadinessProbe } from "@o3co/auth-provider-core";
import { type Express, type Router } from "express";
import type { Metrics } from "./metrics.mjs";
export interface MountRoutesOptions {
    /** The router `createApp` composed (`handle.router`). */
    readonly router: Router;
    /** The readiness probes the builders registered (`handle.readinessProbes`). */
    readonly probes: readonly ReadinessProbe[];
    /** Per-probe deadline, in milliseconds: `config.http.readinessTimeoutMs`. */
    readonly readinessTimeoutMs: number;
    readonly metrics: Metrics;
    readonly logger: Logger;
}
/** Mount the host's routes, the composed router and the terminal error handler on `app`. */
export declare function mountRoutes(app: Express, options: MountRoutesOptions): void;
//# sourceMappingURL=routes.d.mts.map