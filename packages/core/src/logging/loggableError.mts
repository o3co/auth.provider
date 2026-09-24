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
 * library or a store talking to another system. An allowlist of fields, not
 * the error, under one rule: a message written by code in this process from
 * fixed text is kept; a message a parser or a peer wrote is not trusted. An
 * error built from a parsed upstream response carries whatever that response
 * said — an OAuth library puts the token answer it refused on the cause
 * chain, a JSON parser quotes the text it could not parse, a Redis reply
 * error echoes the command it refused — and a token answer or a store write
 * is credentials. No state.
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
	/** The upstream's `error_description`, when it is within RFC 6749 §5.2's character set. */
	readonly error_description?: string;
	/** A Response the library put on the error — its cause, or its own `response`. */
	readonly response?: { readonly status: number; readonly contentType?: string };
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
 * Redis quotes the leading arguments of a command it refused after this, in
 * the server's own text — so whichever client carries it: redis-errors'
 * ReplyError (ioredis), node-redis's ErrorReply (named plain "Error").
 */
const REDIS_ECHOED_ARGS = /, with args beginning with:[\s\S]*$/;

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
 * Project an error onto the fields a log line may carry.
 *
 * Kept: `name`; `message`, except that a SyntaxError's is dropped (V8's
 * JSON.parse and body-parser both quote the input — keep only `position N`)
 * and Redis's echo of a refused command's arguments is cut; a string or
 * numeric `code`; an integer `status`; a string `type`; an `error` and an
 * `error_description` within RFC 6749 §5.2's character set; the status and
 * content type of a Response on the cause or on `response`; and the Error
 * causes the same way, three deep. Every string is capped at 256 characters.
 *
 * Never kept: a cause that is a plain object — where openid-client and
 * oauth4webapi put the answer they refused (`cause.cause.body` on a token
 * response: the access and refresh tokens) — a field of another shape
 * (`command`, `body`, `buffer`: a store's command, a parser's input), and
 * anything of a thrown value that is not an Error but its `typeof`.
 *
 * A logger that prints the whole error — every own property, `cause`
 * included — would otherwise write an upstream's credentials to the log. The
 * shipped `consoleLogger` and pino's default serializer do not, but a
 * deployment chooses its logger, so a call site that logs a library's or a
 * store's error hands the logger this instead of the error. It never throws.
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
	const description = read(err, "error_description");
	const cause = read(err, "cause");
	const response = responseFields(cause) ?? responseFields(read(err, "response"));

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

	return {
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
		...(typeof description === "string" && OAUTH_ERROR_TEXT.test(description)
			? { error_description: capped(description) }
			: {}),
		...(response !== undefined ? { response } : {}),
		...(isError(cause) && depth < MAX_CAUSE_DEPTH ? { cause: project(cause, depth + 1) } : {}),
	};
}
