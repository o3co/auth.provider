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
 * Structured logger interface for @o3co/auth-provider internals.
 *
 * Pino-compatible for the call shapes in use here. A pino instance satisfies
 * this interface without an adapter; consumers may inject any object exposing
 * these six methods + child(). Not full pino parity — pino additionally
 * supports `Error` as the first argument and printf-style interpolation via
 * the trailing `...args` (covered by the `unknown[]` rest below for assignment
 * compatibility, but not interpreted by the default `consoleLogger`).
 *
 * The first argument may be either a structured object or a plain string.
 * When an object is passed, structured fields are propagated by the
 * implementation; the optional second `msg` becomes the human-readable
 * summary. Object-first is preferred at security-relevant call sites: it makes
 * field-path-based redaction (PII, credentials) tractable, since the keys are
 * directly inspectable rather than embedded inside a format string. The
 * trailing `...args: unknown[]` rest preserves source compatibility with
 * legacy string-first call sites that pass an extra error/value as the second
 * argument; the default `consoleLogger` forwards them verbatim to `console.*`.
 *
 * BREAKING CHANGE (v0.5.1, D-4): the prior interface had only
 * `warn(message: string, ...args: unknown[]): void`. Implementations conforming
 * to that older shape must now add `trace`, `debug`, `info`, `error`, `fatal`,
 * and `child`. The console-backed default (`consoleLogger`) satisfies this
 * interface; consumers without a structured logger should rely on it via the
 * optional `ComponentMap.logger` slot.
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
 * `@o3co/auth-provider-core`. Declared via TypeScript declaration merge per
 * the existing pattern (see e.g. `ratelimit/types.mts:54-66`).
 */
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly logger?: Logger;
	}
}
