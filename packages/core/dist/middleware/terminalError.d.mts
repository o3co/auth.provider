import type { ErrorRequestHandler } from "express";
import type { Logger } from "../logging/Logger.mjs";
/**
 * The handler `assembleApp` mounts last on the router it builds, logging on
 * `logger` — the composition's `logger` component, or `consoleLogger`.
 * Exported for a host that mounts routes of its own beside that router (a
 * health check, a metrics scrape): mounted after them, it gives their errors
 * the same answer.
 */
export declare const terminalErrorHandler: (logger: Logger) => ErrorRequestHandler;
//# sourceMappingURL=terminalError.d.mts.map