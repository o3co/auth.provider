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

/**
 * The six emitting levels plus `silent`, which emits nothing.
 *
 * `silent` is a threshold value, not something a call site passes — there is no
 * `logger.silent(...)`.
 */
export type LogLevel = "trace" | "debug" | "info" | "warn" | "error" | "fatal" | "silent";

/**
 * Structured logger interface for @o3co/auth-provider internals.
 *
 * Pino-compatible for the call shapes used here: a pino instance satisfies it
 * without an adapter. Not full pino parity: pino also takes an `Error` first
 * and interpolates the trailing `...args`; the `unknown[]` rest keeps pino
 * assignable, but the default `consoleLogger` interprets neither.
 *
 * Prefer object-first at security-relevant call sites: keys can be redacted
 * by field path (PII, credentials), which a format string does not allow. The
 * trailing `...args` keeps string-first call sites compiling; `consoleLogger`
 * forwards them verbatim to `console.*`, and is the fallback when the
 * optional `ComponentMap.logger` slot is empty.
 *
 * A logger must not throw; a throwing logger may turn an outage into a
 * rejection.
 */
export interface Logger {
	// Two overload shapes mirror pino: object-first carries structured
	// bindings + optional message, string-first carries a printf-style
	// message + any extra arguments (forwarded verbatim by `consoleLogger`).
	trace(obj: Record<string, unknown>, msg?: string, ...args: unknown[]): void;
	trace(msg: string, ...args: unknown[]): void;
	debug(obj: Record<string, unknown>, msg?: string, ...args: unknown[]): void;
	debug(msg: string, ...args: unknown[]): void;
	info(obj: Record<string, unknown>, msg?: string, ...args: unknown[]): void;
	info(msg: string, ...args: unknown[]): void;
	warn(obj: Record<string, unknown>, msg?: string, ...args: unknown[]): void;
	warn(msg: string, ...args: unknown[]): void;
	error(obj: Record<string, unknown>, msg?: string, ...args: unknown[]): void;
	error(msg: string, ...args: unknown[]): void;
	fatal(obj: Record<string, unknown>, msg?: string, ...args: unknown[]): void;
	fatal(msg: string, ...args: unknown[]): void;
	/**
	 * Return a child logger that prepends `bindings` to every subsequent log
	 * call. Per-call object fields win over child bindings on key collision
	 * (last-write-wins, mirroring pino).
	 */
	child(bindings: Record<string, unknown>): Logger;
}

/**
 * Optional `logger` slot on the manifest `ComponentMap`. When absent, modules
 * fall back to the `consoleLogger` default exported from
 * `@o3co/auth-provider-core`.
 */
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly logger?: Logger;
	}
}

/**
 * The narrow logger shape that injection seams accept.
 *
 * `Logger` is what this project logs through; `EventLogger` is what it may
 * demand of a caller. At seams a composition root wires by hand (a readiness
 * route, an adapter reporting connection errors), a host logger that lacks
 * `trace` / `fatal` / `child`, or requires a message argument, satisfies
 * neither `Logger` nor `Pick<Logger, "error">` (which keeps both overloads);
 * the standalone template's logger is such a case. Seams that only emit a
 * named structured event take this; use `Logger` where its full surface is
 * used.
 */
export interface EventLogger {
	warn(obj: Record<string, unknown>, msg: string): void;
	error(obj: Record<string, unknown>, msg: string): void;
}
