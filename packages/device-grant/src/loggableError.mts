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
 *   - `stack` keeps the frames and nothing of the header before them — the
 *     header is `name: message`, and the message is the untrusted part, so
 *     it is cut by the message's own text: a line of the message shaped
 *     like a frame is cut with it. At most {@link LOGGED_STACK_MAX_FRAMES}
 *     frames and {@link LOGGED_STACK_MAX_LENGTH} characters, whichever
 *     comes first. No `stack` when it has no frames, or when its header no
 *     longer carries the message (rewritten after V8 formatted the stack,
 *     which it does on the first read of `stack`): there is then no telling
 *     the header's lines from the frames;
 *   - every other string kept is capped at {@link LOGGED_STRING_MAX_LENGTH};
 *   - a field whose read throws (a getter) is left out, so the projection
 *     itself never throws.
 *
 * The frames are what locates a failure in this package's own code — a
 * `TypeError` on data it did not expect — which name and message alone do
 * not.
 *
 * What a kept message may still contain: the error's own wording — for a
 * Redis reply, its text before the arguments (`ERR unknown command
 * 'evalsha'`) — and, from an error no rule here anticipates, up to that many
 * characters of whatever it says.
 *
 * In a file of its own rather than in `module.mts`: the device-authorization
 * endpoint logs through it too, and `module.mts` imports that endpoint.
 * {@link guardedRead}, its one way of reading a field, is exported for
 * `module.mts`'s parser-refusal check, which asks the same errors.
 */

/**
 * The longest string the projection keeps. Room for the fixed text of the
 * errors these routes meet — a Redis reply, a Node system error, a
 * `TypeError` — and at most a fragment of anything a message echoes that no
 * rule anticipated.
 */
export const LOGGED_STRING_MAX_LENGTH = 256;

/** The most stack frames the projection keeps. */
export const LOGGED_STACK_MAX_FRAMES = 10;

/** The longest `stack` the projection keeps, frames joined; the cut may fall mid-frame. */
export const LOGGED_STACK_MAX_LENGTH = 2048;

/** A V8 stack frame's line, as it starts. */
const FRAME_PREFIX = "    at ";

/**
 * `target[key]`, read so that the read cannot throw: `{ value }`, or `null`
 * when it threw — a getter, a Proxy's trap. An error handler is handed
 * whatever was thrown, and a handler that throws while asking about it
 * replaces it, in Express's hands, with its own throw.
 */
export const guardedRead = (target: object, key: string): { readonly value: unknown } | null => {
	try {
		return { value: (target as Record<string, unknown>)[key] };
	} catch {
		return null;
	}
};

/**
 * The frames of `stack`, without the header ahead of them. The header is cut
 * by `message`'s own text, not at the first line shaped like a frame, which
 * the message itself may contain. `undefined` when there are no frames, or
 * when the header no longer carries `message`. What the text cannot show is
 * a message rewritten, after the stack was formatted, to a leading part of
 * the one the header carries: the rest of the old message then reads as
 * the start of the frames.
 */
const framesOf = (stack: unknown, message: unknown): string | undefined => {
	if (typeof stack !== "string") return undefined;
	let rest = stack;
	if (typeof message === "string" && message !== "") {
		const at = stack.indexOf(message);
		if (at < 0) return undefined;
		rest = stack.slice(at + message.length);
	}
	const lines = rest.split("\n");
	const first = lines.findIndex((line, index) => index > 0 && line.startsWith(FRAME_PREFIX));
	if (first < 0) return undefined;
	const frames: string[] = [];
	for (const line of lines.slice(first, first + LOGGED_STACK_MAX_FRAMES)) {
		if (!line.startsWith(FRAME_PREFIX)) break;
		frames.push(line);
	}
	return frames.join("\n").slice(0, LOGGED_STACK_MAX_LENGTH);
};

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
	const read = (key: string): unknown => guardedRead(error as object, key)?.value;
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
	const stack = framesOf(read("stack"), message);
	if (stack !== undefined) out.stack = stack;
	return out;
};
