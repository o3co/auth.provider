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
 * What of an unexpected error the device routes may write to a log.
 *
 * Never the error itself. A body-parser error carries the request body
 * (`body`); an ioredis reply error carries the command it answered
 * (`command.args` — a user code, the approving subject); a `cause` can carry
 * either, and a structured logger serialises all of it. Express's own error
 * handler logged only the stack, and these routes must not log more.
 *
 * `loggableError` keeps an error's `name`, `message`, `type`, `code` and
 * `status`, when they are strings or numbers, and passes the message through
 * `redactErrorMessage`. The two are kept together, and apart from the
 * routes, so they can move into core as one piece.
 */

/**
 * The longest string a projected field may carry. Long enough for the fixed
 * text of the errors these routes meet — a Redis reply ("READONLY You can't
 * write against a read only replica."), a Node system error, a `TypeError` —
 * and short enough that a message echoing something no rule below
 * anticipated carries at most a fragment of it, on one bounded line.
 */
export const LOGGED_FIELD_MAX_LENGTH = 200;

/** `value`, cut to {@link LOGGED_FIELD_MAX_LENGTH} characters with an ellipsis. */
const capped = (value: string): string =>
	value.length > LOGGED_FIELD_MAX_LENGTH
		? `${value.slice(0, LOGGED_FIELD_MAX_LENGTH - 1)}…`
		: value;

/**
 * An error message with what it is known to echo of its input removed:
 *
 *   - redis-errors' `ReplyError` for an unknown command appends
 *     `, with args beginning with: '…' '…'` — the command's first arguments.
 *     That suffix is cut.
 *   - V8's `JSON.parse` `SyntaxError` quotes a snippet of its input —
 *     `Unexpected token 'u', "user_code=…" is not valid JSON`. Everything from
 *     the first `"` is replaced with `<input>`, keeping ` is not valid JSON`.
 *   - Whatever is left is cut at {@link LOGGED_FIELD_MAX_LENGTH}.
 *
 * What the message may still contain: the library's own wording, positions
 * (`at position 38 (line 1 column 39)`), the one character V8 names as the
 * unexpected token, a Redis command name — and, from an error nobody here
 * has seen, up to that many characters of whatever it says.
 */
export const redactErrorMessage = (name: string | undefined, message: string): string => {
	let redacted = message.replace(/, with args beginning with:[\s\S]*$/, "");
	if (name === "SyntaxError") {
		const quote = redacted.indexOf('"');
		if (quote !== -1) {
			const verdict = /" is not valid JSON$/.test(redacted) ? " is not valid JSON" : "";
			redacted = `${redacted.slice(0, quote)}<input>${verdict}`;
		}
	}
	return capped(redacted);
};

/**
 * The fields of `error` a log line may carry — see the file header. A thrown
 * value that is not an object is reported by its type alone.
 */
export const loggableError = (error: unknown): Record<string, string | number> => {
	if (error === null || typeof error !== "object") return { thrown: typeof error };
	const fields = error as Record<string, unknown>;
	const name = typeof fields.name === "string" ? fields.name : undefined;
	const out: Record<string, string | number> = {};
	for (const key of ["name", "message", "type", "code", "status"] as const) {
		const value = fields[key];
		if (typeof value === "number") out[key] = value;
		else if (typeof value === "string") {
			out[key] = key === "message" ? redactErrorMessage(name, value) : capped(value);
		}
	}
	return out;
};
