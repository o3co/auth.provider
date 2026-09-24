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
 * library talking to another system. An allowlist of fields, not the error:
 * an OAuth library puts the response it refused on the error's cause chain,
 * and a token response is credentials. No state.
 */

/** The fields of an error a log line carries, and its Error causes the same way. */
export interface LoggableError {
	readonly name: string;
	readonly message?: string;
	/** A library's error code, e.g. openid-client's `OAUTH_INVALID_RESPONSE`. */
	readonly code?: string | number;
	/** The HTTP status the upstream answered, when the error records one. */
	readonly status?: number;
	/** The upstream's OAuth `error` code (RFC 6749 §5.2), e.g. `invalid_grant`. */
	readonly error?: string;
	readonly cause?: LoggableError;
	/** For a thrown value that is not an Error: its `typeof`, and nothing of its content. */
	readonly type?: string;
}

/** RFC 6749 §5.2 / §A.7: `error = 1*NQSCHAR`, printable ASCII without `"` or `\`. */
const OAUTH_ERROR_CODE = /^[\x20\x21\x23-\x5B\x5D-\x7E]{1,128}$/;

/** How many causes deep the projection follows; a cycle ends here too. */
const MAX_CAUSE_DEPTH = 3;

/**
 * Project an error onto the fields a log line may carry.
 *
 * The Error's `name` and `message`; a `code` that is a string or a number; a
 * numeric `status`; an `error` that is an OAuth error code; and its `cause`,
 * the same way, while the cause is itself an Error. Nothing else — not a
 * cause that is a plain object, which is where openid-client and oauth4webapi
 * put the response they refused (`cause.cause.body` on a token response they
 * could not parse: the access and refresh tokens), not a field of an
 * unexpected shape, and nothing of a thrown value that is not an Error.
 *
 * A logger that prints the whole error — every own property, `cause`
 * included — would otherwise write an upstream's credentials to the log. The
 * shipped `consoleLogger` and pino's default serializer do not, but a
 * deployment chooses its logger, so a call site that logs a library's error
 * hands the logger this instead of the error.
 */
export function loggableError(err: unknown): LoggableError {
	return project(err, 0);
}

function project(err: unknown, depth: number): LoggableError {
	if (!(err instanceof Error)) {
		return { name: "NonError", type: err === null ? "null" : typeof err };
	}
	const fields = err as Error & {
		readonly code?: unknown;
		readonly status?: unknown;
		readonly error?: unknown;
	};
	const { code, status, error, cause } = fields;
	return {
		name: typeof err.name === "string" ? err.name : "Error",
		...(typeof err.message === "string" ? { message: err.message } : {}),
		...(typeof code === "string" || (typeof code === "number" && Number.isFinite(code))
			? { code }
			: {}),
		...(typeof status === "number" && Number.isInteger(status) ? { status } : {}),
		...(typeof error === "string" && OAUTH_ERROR_CODE.test(error) ? { error } : {}),
		...(cause instanceof Error && depth < MAX_CAUSE_DEPTH
			? { cause: project(cause, depth + 1) }
			: {}),
	};
}
