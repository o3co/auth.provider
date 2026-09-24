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
 * `loggableError` — what of an unexpected error the device routes may write to
 * a log. Never the error itself: a body-parser error carries the request body
 * (`body`), an ioredis reply error the command it answered (`command.args` — a
 * user code, the approving subject), a `cause` either, and a structured
 * logger serialises all of it. Express's own error handler logged only the
 * stack, and these routes must not log more.
 *
 * It mirrors the rule core's `loggableError` (`logging/loggableError.mts`)
 * follows, so that once both are merged this file becomes an import:
 *
 *   - a thrown value that is not an `Error` is `{ thrown: typeof value }` —
 *     and so is one whose `Error`-ness cannot even be asked (a Proxy whose
 *     `getPrototypeOf` trap throws, where `Error.isError` is missing);
 *   - of an `Error`: `name`, `message`, `code` and `status` when they are
 *     strings or numbers, and `type` when it is a string (body-parser's and
 *     http-errors' codes);
 *   - a `SyntaxError` keeps no `message` — V8 quotes its input there, and
 *     body-parser's `entity.parse.failed` is one quoting the request body —
 *     only the `position` its message names, as a number of at most ten
 *     digits;
 *   - every other message loses `, with args beginning with:` and everything
 *     after it. The phrase is Redis's own — its reply to an unknown command
 *     quotes the command's first arguments — so the cut is keyed on the
 *     phrase, not on a client library's class: ioredis's `ReplyError` names
 *     itself, node-redis's `ErrorReply` does not;
 *   - every string kept is capped at {@link LOGGED_STRING_MAX_LENGTH};
 *   - a field whose read throws (a getter) is left out, so the projection
 *     itself never throws.
 *
 * What a kept message may still contain: the error's own wording — for a
 * Redis reply, its text before the arguments (`ERR unknown command
 * 'evalsha'`) — and, from an error no rule here anticipates, up to that many
 * characters of whatever it says.
 *
 * In a file of its own rather than in `module.mts`: the device-authorization
 * endpoint logs through it too, and `module.mts` imports that endpoint.
 */

/**
 * The longest string the projection keeps. Room for the fixed text of the
 * errors these routes meet — a Redis reply, a Node system error, a
 * `TypeError` — and at most a fragment of anything a message echoes that no
 * rule anticipated.
 */
export const LOGGED_STRING_MAX_LENGTH = 256;

export const loggableError = (error: unknown): Record<string, string | number> => {
	let isError: boolean;
	try {
		isError =
			(Error as { isError?: (value: unknown) => boolean }).isError?.(error) ??
			error instanceof Error;
	} catch {
		isError = false;
	}
	if (!isError) return { thrown: typeof error };
	const read = (key: string): unknown => {
		try {
			return (error as Record<string, unknown>)[key];
		} catch {
			return undefined;
		}
	};
	const cap = (value: string): string =>
		value.length > LOGGED_STRING_MAX_LENGTH
			? `${value.slice(0, LOGGED_STRING_MAX_LENGTH - 1)}…`
			: value;

	const out: Record<string, string | number> = {};
	const name = read("name");
	if (typeof name === "string") out.name = cap(name);
	const message = read("message");
	if (typeof message === "string") {
		if (name === "SyntaxError") {
			const position = / at position (\d{1,10})(?!\d)/.exec(message)?.[1];
			if (position !== undefined) out.position = Number(position);
		} else {
			out.message = cap(message.replace(/, with args beginning with:[\s\S]*$/, ""));
		}
	}
	const type = read("type");
	if (typeof type === "string") out.type = cap(type);
	for (const key of ["code", "status"] as const) {
		const value = read(key);
		if (typeof value === "number") out[key] = value;
		else if (typeof value === "string") out[key] = cap(value);
	}
	return out;
};
