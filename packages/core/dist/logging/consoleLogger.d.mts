import type { Logger } from "./Logger.mjs";
/**
 * Create a `Logger` instance backed by `console.*`, optionally pre-bound with
 * the given `bindings`. Pass no argument to obtain a logger with no bindings
 * (equivalent to the exported `consoleLogger` singleton).
 */
export declare function createConsoleLogger(bindings?: Record<string, unknown>): Logger;
/**
 * Pre-created root `Logger` (zero bindings) backed by `console.*`. Used as the
 * DI fallback when `ComponentMap.logger` is not provided.
 */
export declare const consoleLogger: Logger;
//# sourceMappingURL=consoleLogger.d.mts.map