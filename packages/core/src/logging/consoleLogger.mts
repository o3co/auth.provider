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

import type { Logger } from "./Logger.mjs";

/**
 * Console-backed `Logger` implementation. Default fallback when no structured
 * logger is injected via the manifest `ComponentMap.logger` slot.
 *
 * Level routing (6 logger levels → 4 available `console.*` methods):
 *   trace → console.debug
 *   debug → console.debug
 *   info  → console.info
 *   warn  → console.warn
 *   error → console.error
 *   fatal → console.error
 *
 * The merged object (child bindings + per-call obj) is passed verbatim to the
 * underlying `console.*` method. No `JSON.stringify` happens here — Node's
 * console formats objects with `util.inspect` for terminal output, while
 * structured log aggregators (Datadog, GCP, etc.) generally consume the
 * unmodified object form. Tests should spy on `console.*` and assert on the
 * call arguments rather than on string output.
 *
 * Per-call obj wins over child bindings on key collision (pino-compatible
 * last-write-wins).
 */
function emit(
	method: "debug" | "info" | "warn" | "error",
	bindings: Record<string, unknown>,
	obj: Record<string, unknown> | string,
	msg: string | undefined,
	args: unknown[],
): void {
	if (typeof obj === "string") {
		// biome-ignore lint/suspicious/noConsole: this IS the default Logger fallback
		console[method]({ ...bindings }, obj, ...(msg !== undefined ? [msg] : []), ...args);
	} else {
		// biome-ignore lint/suspicious/noConsole: this IS the default Logger fallback
		console[method]({ ...bindings, ...obj }, ...(msg !== undefined ? [msg] : []), ...args);
	}
}

/**
 * Create a `Logger` instance backed by `console.*`, optionally pre-bound with
 * the given `bindings`. Pass no argument to obtain a logger with no bindings
 * (equivalent to the exported `consoleLogger` singleton).
 */
export function createConsoleLogger(bindings: Record<string, unknown> = {}): Logger {
	const frozen = { ...bindings };
	const logger: Logger = {
		trace(obj: Record<string, unknown> | string, msg?: string, ...args: unknown[]) {
			emit("debug", frozen, obj, msg, args);
		},
		debug(obj: Record<string, unknown> | string, msg?: string, ...args: unknown[]) {
			emit("debug", frozen, obj, msg, args);
		},
		info(obj: Record<string, unknown> | string, msg?: string, ...args: unknown[]) {
			emit("info", frozen, obj, msg, args);
		},
		warn(obj: Record<string, unknown> | string, msg?: string, ...args: unknown[]) {
			emit("warn", frozen, obj, msg, args);
		},
		error(obj: Record<string, unknown> | string, msg?: string, ...args: unknown[]) {
			emit("error", frozen, obj, msg, args);
		},
		fatal(obj: Record<string, unknown> | string, msg?: string, ...args: unknown[]) {
			emit("error", frozen, obj, msg, args);
		},
		child(extra) {
			return createConsoleLogger({ ...frozen, ...extra });
		},
	};
	return logger;
}

/**
 * Pre-created root `Logger` (zero bindings) backed by `console.*`. Used as the
 * DI fallback when `ComponentMap.logger` is not provided.
 */
export const consoleLogger: Logger = createConsoleLogger();
