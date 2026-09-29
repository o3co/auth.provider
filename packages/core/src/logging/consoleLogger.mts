/*
 * Copyright 2026 1o1 Co. Ltd.
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

import type { Logger, LogLevel } from "./Logger.mjs";

/**
 * Ascending severity. A call is emitted when its level's rank is at least the
 * configured threshold's; `silent` sits above every level so nothing clears it.
 */
const LEVEL_RANK: Record<LogLevel, number> = {
	trace: 10,
	debug: 20,
	info: 30,
	warn: 40,
	error: 50,
	fatal: 60,
	silent: 70,
};

export interface ConsoleLoggerOptions {
	/**
	 * Minimum level to emit. Defaults to `"info"`, so `trace` and `debug` stay
	 * out of production output. `"silent"` drops everything (for test harnesses).
	 */
	readonly level?: LogLevel;
}

/**
 * Writes one log call to `console.*`. Six levels map onto four methods:
 * trace/debug → `debug`, info → `info`, warn → `warn`, error/fatal → `error`.
 *
 * The merged object (child bindings, then the per-call obj, which wins on key
 * collision as in pino) is passed unstringified: Node's console formats it with
 * `util.inspect`, and structured log aggregators consume the object form. Tests
 * should assert on `console.*` call arguments, not on string output.
 *
 * Objects print at the console's default depth; a `loggableError` projection
 * prints whole through its own `util.inspect.custom`.
 */
function emit(
	method: "debug" | "info" | "warn" | "error",
	bindings: Record<string, unknown>,
	obj: Record<string, unknown> | string,
	msg: string | undefined,
	args: unknown[],
): void {
	// No `noConsole` suppression needed: the repo's biome preset does not enable it.
	if (typeof obj === "string") {
		console[method]({ ...bindings }, obj, ...(msg !== undefined ? [msg] : []), ...args);
	} else {
		console[method]({ ...bindings, ...obj }, ...(msg !== undefined ? [msg] : []), ...args);
	}
}

/**
 * Create a `Logger` backed by `console.*`, optionally pre-bound with
 * `bindings`. This is the default when no logger is injected via the manifest
 * `ComponentMap.logger` slot.
 */
export function createConsoleLogger(
	bindings: Record<string, unknown> = {},
	options: ConsoleLoggerOptions = {},
): Logger {
	const frozen = { ...bindings };
	const threshold = LEVEL_RANK[options.level ?? "info"];
	const enabled = (level: LogLevel): boolean => LEVEL_RANK[level] >= threshold;

	const logger: Logger = {
		trace(obj: Record<string, unknown> | string, msg?: string, ...args: unknown[]) {
			if (enabled("trace")) emit("debug", frozen, obj, msg, args);
		},
		debug(obj: Record<string, unknown> | string, msg?: string, ...args: unknown[]) {
			if (enabled("debug")) emit("debug", frozen, obj, msg, args);
		},
		info(obj: Record<string, unknown> | string, msg?: string, ...args: unknown[]) {
			if (enabled("info")) emit("info", frozen, obj, msg, args);
		},
		warn(obj: Record<string, unknown> | string, msg?: string, ...args: unknown[]) {
			if (enabled("warn")) emit("warn", frozen, obj, msg, args);
		},
		error(obj: Record<string, unknown> | string, msg?: string, ...args: unknown[]) {
			if (enabled("error")) emit("error", frozen, obj, msg, args);
		},
		fatal(obj: Record<string, unknown> | string, msg?: string, ...args: unknown[]) {
			if (enabled("fatal")) emit("error", frozen, obj, msg, args);
		},
		// The child inherits the threshold; resetting it would leak debug output
		// from the request-scoped loggers most likely to carry request detail.
		child(extra) {
			return createConsoleLogger({ ...frozen, ...extra }, options);
		},
	};
	return logger;
}

/**
 * Pre-created root `Logger` (zero bindings) backed by `console.*`. Used as the
 * DI fallback when `ComponentMap.logger` is not provided.
 */
export const consoleLogger: Logger = createConsoleLogger();
