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
 *   - `stack` keeps the frames and nothing of the header before them. The
 *     header is `name: message`, and the message is the untrusted part, so
 *     the header is cut by the message's own text — everything up to the end
 *     of its first occurrence — and a line of the message shaped like a
 *     frame goes with it; an empty or absent message leaves a one-line
 *     header, and the first line is dropped. Of what remains, only lines
 *     that are frames (`    at …`) are kept, the first
 *     {@link LOGGED_STACK_MAX_FRAMES} of them, joined and cut at
 *     {@link LOGGED_STACK_MAX_LENGTH} characters. No `stack` when its read
 *     throws or it is not a string, when there are no frames, or when the
 *     stack does not carry the message (rewritten after V8 formatted the
 *     stack, which it does on the first read of `stack`): there is then no
 *     telling the header's lines from the frames;
 *   - every other string kept is capped at {@link LOGGED_STRING_MAX_LENGTH};
 *   - a field whose read throws (a getter) is left out, so the projection
 *     itself never throws;
 *   - every projection has an own, non-enumerable `constructor: undefined`.
 *     pino's error serializer types an error by its constructor's name when
 *     it has one; without this it would log every projection as
 *     `"type": "Object"`, and with it logs the `name` (`"TypeError"`).
 *     Non-enumerable, so nothing that copies or prints the fields sees it.
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

/** A V8 stack frame's line. */
const FRAME = /^ {4}at /;

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
 * The frames of `stack`, without the header ahead of them; `undefined` for
 * none. The header is cut by `message`'s own text — the message as it is
 * now — not at the first line shaped like a frame, which the message itself
 * may contain. What the text cannot show is a message rewritten, after the
 * stack was formatted, to a leading part of the one the header carries: the
 * rest of the old message then reads as the start of the frames, and only
 * its lines shaped like a frame survive the filter.
 */
const framesOf = (stack: unknown, message: unknown): string | undefined => {
	if (typeof stack !== "string") return undefined;
	let rest: string;
	if (typeof message === "string" && message !== "") {
		const at = stack.indexOf(message);
		if (at < 0) return undefined;
		rest = stack.slice(at + message.length);
	} else {
		const newline = stack.indexOf("\n");
		rest = newline < 0 ? "" : stack.slice(newline + 1);
	}
	const frames = rest
		.split("\n")
		.filter((line) => FRAME.test(line))
		.slice(0, LOGGED_STACK_MAX_FRAMES);
	if (frames.length === 0) return undefined;
	return frames.join("\n").slice(0, LOGGED_STACK_MAX_LENGTH);
};

/**
 * `fields`, with the own non-enumerable `constructor: undefined` that makes
 * pino's error serializer type it by `name` rather than as `Object`.
 */
const projection = (fields: Record<string, string | number>): Record<string, string | number> =>
	Object.defineProperty(fields, "constructor", { value: undefined, enumerable: false });

export const loggableError = (error: unknown): Record<string, string | number> => {
	let isError: boolean;
	try {
		isError =
			(Error as { isError?: (value: unknown) => boolean }).isError?.(error) ??
			error instanceof Error;
	} catch {
		isError = false;
	}
	if (!isError) return projection({ thrown: typeof error });
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
	return projection(out);
};
