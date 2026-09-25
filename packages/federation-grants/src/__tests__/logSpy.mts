/*
 * Copyright 2026 1o1 Co. Ltd.
 *
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
 * A logger that records every line with its level, and what a test asks of a
 * line: object-first, the event name as the message and nothing after it, and
 * an `err` that is a projection — plain data — never an Error. Child bindings
 * are merged into each line, as pino writes them.
 */

import type { Logger } from "@o3co/auth-provider-core";
import { expect } from "vitest";

export type Level = "trace" | "debug" | "info" | "warn" | "error" | "fatal";

export interface LoggedLine {
	readonly level: Level;
	readonly args: readonly unknown[];
}

export function createLogSpy(): { readonly logger: Logger; readonly lines: LoggedLine[] } {
	const lines: LoggedLine[] = [];
	const make = (bound: Record<string, unknown>): Logger => {
		const at =
			(level: Level) =>
			(...args: unknown[]): void => {
				const [first, ...rest] = args;
				const merged =
					Object.keys(bound).length > 0 && typeof first === "object" && first !== null
						? [{ ...bound, ...first }, ...rest]
						: args;
				lines.push({ level, args: merged });
			};
		return {
			trace: at("trace"),
			debug: at("debug"),
			info: at("info"),
			warn: at("warn"),
			error: at("error"),
			fatal: at("fatal"),
			child: (bindings: Record<string, unknown>) => make({ ...bound, ...bindings }),
		} as unknown as Logger;
	};
	return { logger: make({}), lines };
}

/** Every line, as `<level> <message>`: what a test pins when it says "exactly this, and nothing else". */
export const written = (lines: readonly LoggedLine[]): string[] =>
	lines.map((line) => `${line.level} ${String(line.args[1] ?? line.args[0])}`);

/**
 * The payload of the one line written as `event`. Fails unless there is
 * exactly one, it is object-first with the event as its message and nothing
 * after it, and its `err` — when it has one — is a projection.
 */
export function payloadOf(lines: readonly LoggedLine[], event: string): Record<string, unknown> {
	const matching = lines.filter((line) => line.args[1] === event);
	expect(matching, `lines written as ${event}`).toHaveLength(1);
	const [payload, message, ...rest] = (matching[0] as LoggedLine).args;
	expect(typeof payload).toBe("object");
	expect(payload).not.toBeNull();
	expect(message).toBe(event);
	expect(rest).toEqual([]);
	const err = (payload as Record<string, unknown>).err;
	if (err !== undefined) {
		expect(err).not.toBeInstanceOf(Error);
		expect(Object.getPrototypeOf(err)).toBe(Object.prototype);
		expect(err).not.toHaveProperty("message");
	}
	return payload as Record<string, unknown>;
}
