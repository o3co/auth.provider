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
 * - `message`: kept, capped at 256 characters, with the two known quoting
 *   shapes removed. A SyntaxError's message is dropped (V8's JSON.parse and
 *   body-parser quote the input); only ` at position N` survives, as
 *   `position`, N at most ten digits and none from a longer number. Redis's
 *   `, with args beginning with: …` is cut from any message. Other text a
 *   peer wrote into a message is kept: the projection cannot tell it from
 *   this process's own.
 * - `error_description`: the one peer-written string kept on purpose — an
 *   operator needs "Token has been expired or revoked." — and only its first
 *   line (split on CRLF or LF), when that line is within RFC 6749 §5.2's
 *   character set (`%x20-21 / %x23-5B / %x5D-7E`) and carries no run of
 *   twenty or more characters from `[A-Za-z0-9._~+/=-]`; capped at 256.
 * - `stack`: the frames, never the header. The header (`name: message`) is
 *   taken to be as many lines as the message has and dropped; of the lines
 *   after it only those starting with four spaces and `at ` are kept; the
 *   first ten of them, joined by `\n`, then cut at 2048 characters. Absent
 *   when no frame is left.
 * - Also kept: `name`; a string or numeric `code`; an integer `status`; a
 *   string `type`; an `error` within §5.2's set; `response: { status,
 *   contentType }` for a Response on the cause or on `response`; and the
 *   Error causes, the same way, three deep. Every string is capped at 256.
 * - Never kept: a cause that is not an Error, any other field (`command`,
 *   `body`, `buffer`), and anything of a thrown value that is not an Error
 *   but its `typeof`, as `thrown`.
 * - It never throws: an error from another realm counts; a throwing getter
 *   drops its field; a value the Error check cannot inspect reads as a
 *   non-Error.
 *
 * No state.
 */

/** The fields of an error a log line carries, and its Error causes the same way. */
export interface LoggableError {
	/** The error's `name`; `"NonError"` for a thrown value that is not an Error. */
	readonly name: string;
	/** Absent for a SyntaxError, which quotes its input; a Redis reply's echoed arguments are cut. */
	readonly message?: string;
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
	 * within RFC 6749 §5.2's character set and carries no run of twenty token
	 * characters. The one peer-written string kept on purpose.
	 */
	readonly error_description?: string;
	/** A Response the library put on the error — its cause, or its own `response`. */
	readonly response?: { readonly status: number; readonly contentType?: string };
	/**
	 * The stack's frames and nothing of its header: at most ten `    at …`
	 * lines, joined by `\n` and cut at 2048 characters. Absent when there
	 * are none.
	 */
	readonly stack?: string;
	readonly cause?: LoggableError;
	/** For a thrown value that is not an Error: its `typeof`, and nothing of its content. */
	readonly thrown?: string;
}

/** The longest string any field keeps. */
const MAX_STRING = 256;

/** How many causes deep the projection follows; a cycle ends here too. */
const MAX_CAUSE_DEPTH = 3;

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
 * AADSTS one — when that line is within RFC 6749 §5.2's character set and
 * carries no token-shaped run. The one peer-written string the projection
 * keeps, because an operator needs it to tell a revoked grant from a broken
 * client.
 */
const descriptionOf = (value: unknown): string | undefined => {
	if (typeof value !== "string") return undefined;
	const firstLine = value.split(/\r?\n/, 1)[0] ?? "";
	if (!OAUTH_ERROR_TEXT.test(firstLine) || TOKEN_RUN.test(firstLine)) return undefined;
	return capped(firstLine);
};

/**
 * Redis quotes the leading arguments of a command it refused after this, in
 * the server's own text — so whichever client carries it: redis-errors'
 * ReplyError (ioredis), node-redis's ErrorReply (named plain "Error").
 */
const REDIS_ECHOED_ARGS = /, with args beginning with:[\s\S]*$/;

/** A V8 stack frame line. */
const FRAME = /^ {4}at /;

/** How many frames, and how many characters of them, a projection keeps. */
const MAX_FRAMES = 10;
const MAX_STACK = 2048;

/** A SyntaxError's offset, and nothing else of its message; a longer number is no offset. */
const SYNTAX_POSITION = / at position (\d{1,10})(?!\d)/;

const capped = (value: string): string => value.slice(0, MAX_STRING);

/** Read one property; a getter that throws leaves the field out rather than the projection. */
const read = (target: object, key: string): unknown => {
	try {
		return (target as Record<string, unknown>)[key];
	} catch {
		return undefined;
	}
};

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
 * The frames of an error's `stack`, and nothing of its header.
 *
 * V8 writes the header as `name: message`, and the message is the untrusted
 * part — it may quote a parser's input or a peer's answer, and it may span
 * lines. So the header is taken to be as many lines as the message has, it is
 * dropped whole, and of what follows only `    at ` lines are kept: a message
 * line shaped like a frame cannot pass for one. At most ten frames, joined by
 * `\n`, then cut at 2048 characters. `undefined` when no frame is left.
 */
const framesOf = (stack: unknown, message: unknown): string | undefined => {
	if (typeof stack !== "string") return undefined;
	const headerLines = typeof message === "string" ? message.split("\n").length : 1;
	const frames = stack
		.split("\n")
		.slice(headerLines)
		.filter((line) => FRAME.test(line))
		.slice(0, MAX_FRAMES);
	return frames.length === 0 ? undefined : frames.join("\n").slice(0, MAX_STACK);
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
 * this instead of the error. It never throws.
 */
export function loggableError(err: unknown): LoggableError {
	return project(err, 0);
}

function project(err: unknown, depth: number): LoggableError {
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
	const stack = framesOf(read(err, "stack"), rawMessage);

	let message: string | undefined;
	let position: number | undefined;
	if (typeof rawMessage === "string") {
		if (name === "SyntaxError") {
			const at = SYNTAX_POSITION.exec(rawMessage);
			position = at ? Number(at[1]) : undefined;
		} else {
			message = capped(rawMessage.replace(REDIS_ECHOED_ARGS, ""));
		}
	}

	const projected: LoggableError = {
		name,
		...(message !== undefined ? { message } : {}),
		...(position !== undefined ? { position } : {}),
		...(typeof code === "string"
			? { code: capped(code) }
			: typeof code === "number" && Number.isFinite(code)
				? { code }
				: {}),
		...(typeof status === "number" && Number.isInteger(status) ? { status } : {}),
		...(typeof type === "string" ? { type: capped(type) } : {}),
		...(typeof error === "string" && OAUTH_ERROR_TEXT.test(error) ? { error: capped(error) } : {}),
		...(errorDescription !== undefined ? { error_description: errorDescription } : {}),
		...(response !== undefined ? { response } : {}),
		...(stack !== undefined ? { stack } : {}),
		...(isError(cause) && depth < MAX_CAUSE_DEPTH ? { cause: project(cause, depth + 1) } : {}),
	};
	// pino's err serializer names `type` after `constructor.name` when that is
	// a function — "Object" for a plain object — and after `name` otherwise.
	// A non-enumerable own `constructor` of `undefined` makes it read `name`
	// ("TypeError"), with no serializer of the deployment's to configure; it is
	// invisible to JSON, to for-in and to `util.inspect`.
	Object.defineProperty(projected, "constructor", { value: undefined, enumerable: false });
	return projected;
}
