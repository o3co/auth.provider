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

/*
 * `loggableError`: what a log line may carry of an error that came out of a
 * library or a store talking to another system — an allowlist of fields,
 * never the error. An error built from a parsed upstream response carries
 * whatever that response said: an OAuth library puts the token answer it
 * refused on the cause chain, a JSON parser quotes the text it could not
 * parse, a Redis reply echoes the command it refused, and ioredis puts that
 * command's arguments — a token record, for a store write under
 * `allow-plaintext` — on the error. What the projection does, exactly:
 *
 * - It is plain data, and what a logger is handed is what the line carries.
 *   It has no `message`: a serializer takes a value with a string `message`
 *   for an Error and rewrites it — pino's err serializer folds each `cause`
 *   into one message and stack and writes none of the cause's fields, and
 *   writes the name over `type`. Every such serializer (pino's `err` and
 *   `errWithCause` among them) hands anything else through untouched, so
 *   under pino's defaults, the standalone template's logger, `consoleLogger`
 *   or any other, every field below reaches the line, at every level.
 * - `detail`: the error's message, capped at 256 characters, with the two
 *   known quoting shapes removed — `detail` (RFC 7807's name for an
 *   occurrence's human-readable explanation) rather than `message`, for the
 *   reason above. A SyntaxError's message is dropped (V8's JSON.parse and
 *   body-parser quote the input); only ` at position N` survives, as
 *   `position`, N at most ten digits and none from a longer number. Redis's
 *   `, with args beginning with: …` is cut from any message. Other text a
 *   peer wrote into a message is kept: the projection cannot tell it from
 *   this process's own.
 * - `error_description`: the one peer-written string kept on purpose — an
 *   operator needs "Token has been expired or revoked." — and only its first
 *   line (split on CRLF or LF), when that line is within RFC 6749 §5.2's
 *   character set (`%x20-21 / %x23-5B / %x5D-7E`), cut at the start of the
 *   space-delimited word that holds its first run of twenty or more
 *   characters from `[A-Za-z0-9._~+/=-]`, and trimmed; omitted when nothing
 *   is left; capped at 256.
 * - `stack`: the frames, never the header. The stack must start with the
 *   whole header V8 writes — `name: message`, Node's `name [code]:
 *   message`, and for an empty message also `name` or `name [code]` — ending its
 *   line, and the header is dropped; a stack that does not (a message
 *   rewritten after V8 formatted it, a message that is not a string) gives
 *   no stack. After it, the unbroken run of lines starting with four spaces
 *   and `at ` is kept (it ends at the first line that is not one); the
 *   first ten, joined by `\n`, then cut at 2048 characters. Absent when no
 *   frame is left or `stack` cannot be read. See `framesOf` for what can
 *   still pass for a frame.
 * - Also kept: `name`; a string or numeric `code`; an integer `status`; a
 *   string `type`; an `error` within §5.2's set; `response: { status,
 *   contentType }` for a Response on the cause or on `response`; and the
 *   Error causes, the same way, three deep. Every string is capped at 256.
 * - Closed-set fields a store's or a client's error records, kept because
 *   their shape cannot hold free text: an own `reason` that is a code —
 *   lowercase words joined by `_` or `-`, at most 64 characters
 *   (`unreachable`, `expired-at-issue`) — and an own `<word>Status` field
 *   holding an HTTP status, 100–599, at most four of them (`storeStatus`: an
 *   upstream's answer an error records beside its own `status`, which
 *   Express reads as this server's).
 * - An AggregateError's members (any error's `errors` array): of its first
 *   {@link LOGGED_AGGREGATE_MAX_ERRORS}, the Errors, projected as causes are
 *   and within the same three levels, as `aggregateErrors` — the name pino
 *   writes a raw AggregateError's members under, so one query finds both —
 *   and how many members are not among them, as `aggregateErrorsOmitted`.
 *   Neither field when none of those five is an Error.
 * - A budget for the line: at most {@link LOGGED_MAX_PROJECTIONS}
 *   projections, the error and its causes and members together, taken
 *   nearest first (breadth first: the error's own cause and members before
 *   any of theirs). A member the budget leaves out counts in
 *   `aggregateErrorsOmitted`; a cause it leaves out leaves
 *   `causeOmitted: true`.
 * - Never kept: a cause or a member that is not an Error, any other field
 *   (`command`, `body`, `buffer`), and anything of a thrown value that is
 *   not an Error but its `typeof`, as `thrown`.
 * - It never throws: an error from another realm counts; a throwing getter
 *   drops its field; a value the Error check cannot inspect reads as a
 *   non-Error.
 *
 * No state.
 */

/**
 * The fields of an error a log line carries, and its Error causes the same
 * way: a plain object, with no `message`, so that no serializer takes it for
 * an Error and rewrites it — the line carries exactly these fields.
 */
export interface LoggableError {
	/** The error's `name`; `"NonError"` for a thrown value that is not an Error. */
	readonly name: string;
	/**
	 * The error's message. Absent for a SyntaxError, which quotes its input; a
	 * Redis reply's echoed arguments are cut. Not `message`, which would make
	 * a serializer take the projection for an Error.
	 */
	readonly detail?: string;
	/** A SyntaxError's `position N`, read out of its message. */
	readonly position?: number;
	/** A library's error code, e.g. openid-client's `OAUTH_INVALID_RESPONSE`. */
	readonly code?: string | number;
	/** The HTTP status the error records, e.g. an OAuth refusal's or body-parser's. */
	readonly status?: number;
	/** A string `type`, e.g. body-parser's `entity.too.large`. */
	readonly type?: string;
	/** The upstream's OAuth `error` code (RFC 6749 §5.2), e.g. `invalid_grant`. */
	readonly error?: string;
	/**
	 * The upstream's `error_description`: its first line, when that line is
	 * within RFC 6749 §5.2's character set, cut at the start of the word that
	 * holds its first run of twenty token characters, and trimmed. The one
	 * peer-written string kept on purpose.
	 */
	readonly error_description?: string;
	/** A Response the library put on the error — its cause, or its own `response`. */
	readonly response?: { readonly status: number; readonly contentType?: string };
	/**
	 * The stack's frames and nothing of its header: at most
	 * {@link LOGGED_STACK_MAX_FRAMES} `    at …` lines, joined by `\n` and cut
	 * at {@link LOGGED_STACK_MAX_LENGTH} characters. Absent when there are
	 * none, when `stack` cannot be read, or when it does not start with the
	 * header V8 writes for the error's name, code and message.
	 */
	readonly stack?: string;
	readonly cause?: LoggableError;
	/** `true` when the error has an Error cause that {@link LOGGED_MAX_PROJECTIONS} left out. */
	readonly causeOmitted?: true;
	/**
	 * An own `reason` that is a code — lowercase words joined by `_` or `-`,
	 * at most 64 characters — e.g. a Store transport failure's `unreachable`.
	 */
	readonly reason?: string;
	/**
	 * An AggregateError's members: of its first
	 * {@link LOGGED_AGGREGATE_MAX_ERRORS}, the Errors, projected the same way.
	 */
	readonly aggregateErrors?: readonly LoggableError[];
	/**
	 * How many of the members are not in `aggregateErrors`: past the first
	 * five, not an Error, or left out by {@link LOGGED_MAX_PROJECTIONS}.
	 */
	readonly aggregateErrorsOmitted?: number;
	/** For a thrown value that is not an Error: its `typeof`, and nothing of its content. */
	readonly thrown?: string;
	/**
	 * An own `<word>Status` field holding an HTTP status (100–599), at most
	 * four: an upstream's answer an error records beside its own `status`,
	 * e.g. a Store refusal's `storeStatus`.
	 */
	readonly [statusField: `${string}Status`]: number | undefined;
}

/** The longest string any field keeps. */
export const LOGGED_STRING_MAX_LENGTH = 256;

/** How many causes (or AggregateError members) deep the projection follows; a cycle ends here too. */
const MAX_CAUSE_DEPTH = 3;

/** The most AggregateError members the projection looks at, at each level. */
export const LOGGED_AGGREGATE_MAX_ERRORS = 5;

/**
 * The most projections one line holds: the error, its causes and its
 * members, all levels together. Each is capped — every string at 256
 * characters, the stack at 2048 — so a line stays under about 64 KB.
 */
export const LOGGED_MAX_PROJECTIONS = 16;

/**
 * A `reason` that is a code: lowercase words joined by `_` or `-`. No space,
 * capital or digit, so no sentence, number or token fits; at most
 * {@link REASON_MAX_LENGTH} characters.
 */
const REASON_CODE = /^[a-z]+(?:[_-][a-z]+)*$/;
const REASON_MAX_LENGTH = 64;

/** A field that records an HTTP status beside `status`: `storeStatus`, `upstreamStatus`. */
const STATUS_FIELD = /^[a-z][A-Za-z]{0,31}Status$/;

/** The most `<word>Status` fields the projection keeps. */
const MAX_STATUS_FIELDS = 4;

/** RFC 6749 §5.2: `error` and `error_description` are `%x20-21 / %x23-5B / %x5D-7E`. */
const OAUTH_ERROR_TEXT = /^[\x20\x21\x23-\x5B\x5D-\x7E]+$/;

/**
 * Twenty or more characters that could be a token (base64url, base64, a
 * JWT's segments, a hex string). An IdP that echoes the credential it refused
 * — legacy Spring Security's "Invalid refresh token: <the token>" — writes
 * one; a sentence does not.
 */
const TOKEN_RUN = /[A-Za-z0-9._~+/=-]{20,}/;

/**
 * An upstream's `error_description`: its first line — Azure AD puts a Trace
 * ID, a Correlation ID and a timestamp on CRLF-separated lines after the
 * AADSTS one — when that line is within RFC 6749 §5.2's character set, cut
 * at the start of the word that holds its first token-shaped run, and
 * trimmed. The word goes whole, so no part of the token and no fragment of
 * the word is left: "Invalid refresh token: <the token>" (or "…: abc:<the
 * token>") keeps "Invalid refresh token:", AADSTS700016 keeps "Application
 * with identifier", a redirect URI named by Azure AD or Okta goes with its
 * `https:`. §5.2's set has no tab, so a word ends at a space. Omitted when
 * nothing is left. The one peer-written string the projection keeps,
 * because an operator needs it to tell a revoked grant from a broken client.
 */
const descriptionOf = (value: unknown): string | undefined => {
	if (typeof value !== "string") return undefined;
	const firstLine = value.replace(/\r?\n[\s\S]*$/, "");
	if (!OAUTH_ERROR_TEXT.test(firstLine)) return undefined;
	const run = TOKEN_RUN.exec(firstLine);
	const wordStart = run === null ? firstLine.length : firstLine.lastIndexOf(" ", run.index) + 1;
	const kept = firstLine.slice(0, wordStart).trim();
	return kept === "" ? undefined : capped(kept);
};

/**
 * Redis quotes the leading arguments of a command it refused after this, in
 * the server's own text — so whichever client carries it: redis-errors'
 * ReplyError (ioredis), node-redis's ErrorReply (named plain "Error").
 */
const REDIS_ECHOED_ARGS = /, with args beginning with:[\s\S]*$/;

/** A V8 stack frame line. */
const FRAME = /^ {4}at /;

/** The most stack frames the projection keeps. */
export const LOGGED_STACK_MAX_FRAMES = 10;

/** The longest `stack` the projection keeps, frames joined; the cut may fall mid-frame. */
export const LOGGED_STACK_MAX_LENGTH = 2048;

/** A SyntaxError's offset, and nothing else of its message; a longer number is no offset. */
const SYNTAX_POSITION = / at position (\d{1,10})(?!\d)/;

const capped = (value: string): string => value.slice(0, LOGGED_STRING_MAX_LENGTH);

/**
 * `target[key]`, read so that the read cannot throw: `{ value }`, or `null`
 * when it threw — a getter, a Proxy's trap. The projection is handed
 * whatever was thrown, and must not throw while asking about it.
 */
export const guardedRead = (target: object, key: string): { readonly value: unknown } | null => {
	try {
		return { value: (target as Record<string, unknown>)[key] };
	} catch {
		return null;
	}
};

/** One property, or `undefined` when reading it threw: that field is left out. */
const read = (target: object, key: string): unknown => guardedRead(target, key)?.value;

/**
 * An Error from this realm or another (`node:vm`, a worker's structured
 * clone). `Error.isError` where the runtime has it (Node 24+); on Node 22 the
 * fallback asks the value for its prototype and its tag, which a Proxy may
 * answer by throwing — any throw reads as "not an Error".
 */
const isError = (value: unknown): value is object => {
	try {
		const brand = (Error as { isError?: (candidate: unknown) => boolean }).isError;
		if (typeof brand === "function") return brand(value);
		return (
			value instanceof Error ||
			(typeof value === "object" &&
				value !== null &&
				Object.prototype.toString.call(value) === "[object Error]")
		);
	} catch {
		return false;
	}
};

/**
 * Where the header written for `name`, a string `code` and `message` ends in
 * `stack` — `name: message` or `name [code]: message`, and for an empty
 * message also `name` or `name [code]` — when the stack starts with it and it
 * ends its line; `-1` otherwise. V8 and Node write an empty message's header
 * as the name alone; a source-map formatter (source-map-support, vitest's)
 * writes `name: ` — both are the header.
 */
const headerEnd = (stack: string, name: string, code: unknown, message: string): number => {
	const names = typeof code === "string" ? [name, `${name} [${code}]`] : [name];
	for (const named of names) {
		for (const header of message === "" ? [`${named}: `, named] : [`${named}: ${message}`]) {
			const next = stack.charAt(header.length);
			if (stack.startsWith(header) && (next === "" || next === "\n")) return header.length;
		}
	}
	return -1;
};

/**
 * The frames of an error's `stack`, and nothing of the header ahead of them
 * — pinned by the `stack` vectors in `__tests__/loggableError.test.mts`:
 *
 * 1. `stack` or `message` not a string (or its read threw): no stack.
 * 2. The header is what V8 writes from the error's `name` (a non-string one
 *    compares as `"Error"`), a string `code` and `message`: `name:
 *    message`, or Node's `name [code]: message`; for an empty message, also
 *    `name` or `name [code]`. The stack must start with one of them, and
 *    the header must end its line (a line break or the end of the stack
 *    follows it). The message is the untrusted part: matched whole, from
 *    the start, a message line shaped like a frame goes with the header —
 *    never counted in lines. A stack that starts otherwise (the message
 *    rewritten after V8 formatted the stack, which it does on the first
 *    read of `stack`, to text found inside the name, part-way along the
 *    header's line, or nowhere in it) means no stack, because the header can
 *    no longer be told from the frames.
 * 3. After the header, the unbroken run of `    at ` lines starting at the
 *    first such line is kept, and it ends at the first line that is not one
 *    — so a section appended after the frames ("Caused by: …") is not kept,
 *    frame-shaped lines in it included.
 * 4. The first {@link LOGGED_STACK_MAX_FRAMES} of the run, joined by `\n`,
 *    then cut at {@link LOGGED_STACK_MAX_LENGTH} characters. No frame: no
 *    stack.
 *
 * What the text cannot show, and so could still pass for frames:
 * - a message rewritten, after the stack was formatted, to a leading part
 *   of itself that ends at one of its own line breaks: the header V8 would
 *   write for the new message, and the old message's later lines follow it
 *   — its `    at `-shaped lines, if any, read as frames;
 * - a `stack` assigned by hand with a frame-shaped line that carries data:
 *   it is a frame by every test this can make.
 */
const framesOf = (
	stack: unknown,
	name: unknown,
	code: unknown,
	message: unknown,
): string | undefined => {
	if (typeof stack !== "string" || typeof message !== "string") return undefined;
	const end = headerEnd(stack, typeof name === "string" ? name : "Error", code, message);
	if (end < 0) return undefined;
	// The header ends its line: the frames are on the lines after it.
	const lines = stack.slice(end).split("\n").slice(1);
	const first = lines.findIndex((line) => FRAME.test(line));
	if (first < 0) return undefined;
	const frames: string[] = [];
	for (const line of lines.slice(first)) {
		if (!FRAME.test(line) || frames.length === LOGGED_STACK_MAX_FRAMES) break;
		frames.push(line);
	}
	return frames.join("\n").slice(0, LOGGED_STACK_MAX_LENGTH);
};

/** An own `reason` that is a code; `undefined` for anything else, or when asking throws. */
const reasonOf = (err: object): string | undefined => {
	try {
		if (!Object.hasOwn(err, "reason")) return undefined;
	} catch {
		return undefined;
	}
	const reason = read(err, "reason");
	return typeof reason === "string" &&
		reason.length <= REASON_MAX_LENGTH &&
		REASON_CODE.test(reason)
		? reason
		: undefined;
};

/**
 * The error's own `<word>Status` fields that hold an HTTP status, in key
 * order, at most {@link MAX_STATUS_FIELDS}. Nothing when the keys cannot be
 * listed (a Proxy's trap).
 */
const statusFieldsOf = (err: object): Record<string, number> => {
	let keys: string[];
	try {
		keys = Object.keys(err);
	} catch {
		return {};
	}
	const kept: Record<string, number> = {};
	let count = 0;
	for (const key of keys) {
		if (count === MAX_STATUS_FIELDS) break;
		if (!STATUS_FIELD.test(key)) continue;
		const value = read(err, key);
		if (typeof value === "number" && Number.isInteger(value) && value >= 100 && value <= 599) {
			kept[key] = value;
			count++;
		}
	}
	return kept;
};

/**
 * An AggregateError's member candidates: of its first
 * {@link LOGGED_AGGREGATE_MAX_ERRORS} members, the Errors, and how many
 * members it has. `null` for an `errors` that is not an array or cannot be
 * read (a revoked Proxy throws even to `Array.isArray`), and when none of
 * those members is an Error — a validation library's `errors` of plain issue
 * objects.
 */
const membersOf = (err: object): { readonly errors: object[]; readonly total: number } | null => {
	const errors = read(err, "errors");
	let total: unknown;
	try {
		if (!Array.isArray(errors)) return null;
		total = errors.length;
	} catch {
		return null;
	}
	if (typeof total !== "number" || !Number.isInteger(total) || total < 0) return null;
	const candidates: object[] = [];
	for (let index = 0; index < Math.min(total, LOGGED_AGGREGATE_MAX_ERRORS); index++) {
		const member = read(errors as object, String(index));
		if (isError(member)) candidates.push(member);
	}
	return candidates.length === 0 ? null : { errors: candidates, total };
};

/** A fetch `Response`, read structurally so that one from another realm counts too. */
const responseFields = (value: unknown): LoggableError["response"] | undefined => {
	if (typeof value !== "object" || value === null) return undefined;
	const status = read(value, "status");
	const headers = read(value, "headers");
	if (typeof status !== "number" || !Number.isInteger(status)) return undefined;
	if (typeof headers !== "object" || headers === null) return undefined;
	const get = read(headers, "get");
	if (typeof get !== "function") return undefined;
	let contentType: unknown;
	try {
		contentType = get.call(headers, "content-type");
	} catch {
		contentType = undefined;
	}
	return {
		status,
		...(typeof contentType === "string" ? { contentType: capped(contentType) } : {}),
	};
};

/**
 * Project an error onto the fields a log line may carry — the rules are the
 * file header's.
 *
 * A logger that prints the whole error writes what its peer said to the
 * log. Before this projection both shipped paths did so for a store error:
 * pino's err serializer copies every enumerable property of an error —
 * ioredis's `command.args` included — and `consoleLogger` hands the error to
 * `console.*`, whose inspection prints them. A deployment chooses its logger,
 * so a call site that logs a library's or a store's error hands the logger
 * this instead of the error, and every logger writes it as it is. It never
 * throws.
 */
export function loggableError(err: unknown): LoggableError {
	const root = fieldsOf(err);
	// Breadth first, so the budget goes to the error's own cause and members
	// before any of theirs. Each entry is an Error already projected, whose
	// cause and members are still to be attached.
	const pending: Array<{ readonly err: unknown; readonly depth: number; readonly into: Draft }> = [
		{ err, depth: 0, into: root },
	];
	let left = LOGGED_MAX_PROJECTIONS - 1;
	for (let next = 0; next < pending.length; next++) {
		const { err: node, depth, into } = pending[next] as (typeof pending)[number];
		if (!isError(node) || depth >= MAX_CAUSE_DEPTH) continue;
		const cause = read(node, "cause");
		if (isError(cause)) {
			if (left > 0) {
				left--;
				into.cause = fieldsOf(cause);
				pending.push({ err: cause, depth: depth + 1, into: into.cause });
			} else {
				into.causeOmitted = true;
			}
		}
		const members = membersOf(node);
		if (members !== null) {
			const kept: Draft[] = [];
			for (const member of members.errors) {
				if (left === 0) break;
				left--;
				const projected = fieldsOf(member);
				kept.push(projected);
				pending.push({ err: member, depth: depth + 1, into: projected });
			}
			if (kept.length > 0) into.aggregateErrors = kept;
			if (members.total > kept.length) into.aggregateErrorsOmitted = members.total - kept.length;
		}
	}
	return root;
}

/** A projection under construction: its cause and members are attached after its own fields. */
type Draft = {
	-readonly [K in keyof LoggableError]: K extends "cause"
		? Draft | undefined
		: K extends "aggregateErrors"
			? Draft[] | undefined
			: LoggableError[K];
};

/** The error's own fields — everything but its cause and members, which `loggableError` attaches. */
function fieldsOf(err: unknown): Draft {
	if (!isError(err)) {
		return { name: "NonError", thrown: err === null ? "null" : typeof err };
	}
	const rawName = read(err, "name");
	const name = typeof rawName === "string" ? capped(rawName) : "Error";
	const rawMessage = read(err, "message");
	const code = read(err, "code");
	const status = read(err, "status");
	const type = read(err, "type");
	const error = read(err, "error");
	const errorDescription = descriptionOf(read(err, "error_description"));
	const cause = read(err, "cause");
	const response = responseFields(cause) ?? responseFields(read(err, "response"));
	const stack = framesOf(read(err, "stack"), rawName, code, rawMessage);
	const reason = reasonOf(err);

	let detail: string | undefined;
	let position: number | undefined;
	if (typeof rawMessage === "string") {
		if (name === "SyntaxError") {
			const at = SYNTAX_POSITION.exec(rawMessage);
			position = at ? Number(at[1]) : undefined;
		} else {
			detail = capped(rawMessage.replace(REDIS_ECHOED_ARGS, ""));
		}
	}

	return {
		name,
		...(detail !== undefined ? { detail } : {}),
		...(position !== undefined ? { position } : {}),
		...(typeof code === "string"
			? { code: capped(code) }
			: typeof code === "number" && Number.isFinite(code)
				? { code }
				: {}),
		...(typeof status === "number" && Number.isInteger(status) ? { status } : {}),
		...statusFieldsOf(err),
		...(reason !== undefined ? { reason } : {}),
		...(typeof type === "string" ? { type: capped(type) } : {}),
		...(typeof error === "string" && OAUTH_ERROR_TEXT.test(error) ? { error: capped(error) } : {}),
		...(errorDescription !== undefined ? { error_description: errorDescription } : {}),
		...(response !== undefined ? { response } : {}),
		...(stack !== undefined ? { stack } : {}),
	};
}
