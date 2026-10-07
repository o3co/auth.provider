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
 * The last handler on the router `createApp` returns: the answer to an error
 * a route let through, whatever module contributed the route.
 *
 * The OAuth, session and WebAuthn routers parse their own bodies and have no
 * error handler, and no module is obliged to catch everything it can throw.
 * Such an error left the router for whatever the host had after it — Express's
 * final handler unless the host copied the standalone template's: an HTML
 * page, with the stack outside production, where V8's JSON error quotes the
 * body it could not parse. `assembleApp` mounts this after every route, so
 * the router answers its own errors, as the device-grant and federation-grant
 * routers already answer theirs inside themselves:
 *
 * - A body parser's refusal is the client's mistake, answered in RFC 6749
 *   §5.2's envelope with a fixed description and logged nowhere (a client can
 *   send one at will): body-parser's errors are `http-errors` with `expose:
 *   true` and a 4xx `status` — a body over the limit or with too many
 *   parameters is `413 body_too_large`, a charset or `Content-Encoding` it
 *   cannot decode `415 unsupported_encoding`, and what it could not read as
 *   sent `400 malformed_body` — by body-parser's own `type`
 *   (`entity.parse.failed`, `entity.verify.failed`, `request.aborted`,
 *   `request.size.invalid`, `querystring.parse.rangeError`) or, for a body
 *   that does not decompress, the decoder's `code` (zlib's `Z_…` for gzip
 *   and deflate, Node's `ERR__ERROR_FORMAT_…` for brotli). A path parameter Express could
 *   not decode is `400 malformed_path`. Only `expose`, `status`, `type` and
 *   `code` are read, never the message, which quotes the body. Any other
 *   `expose`d 4xx — a 400 included — is an `http-errors` refusal that says
 *   it is the client's (a 404, a 401): it keeps its status, answered
 *   `invalid_request` / `request_refused`, logged nowhere, with the one
 *   header its status owes the client when the refusal carries it (a 401's
 *   `WWW-Authenticate`, a 405's `Allow`, up to 1 KiB; a longer value, or one
 *   no header can hold, is dropped).
 * - Anything else is `500 server_error` (`unexpected_error`), logged once at
 *   error as `unhandled_request_error` with `endpoint` (the path, through
 *   `auditErrorText`) and the error's `loggableError` projection — never the
 *   error, whose fields can carry what a store or a peer said.
 * - A response whose headers already went out cannot be answered: it is
 *   logged the same way, with `headersSent: true`, and — while it is still
 *   being written — its connection closed, as Express's final handler would
 *   close it, without the final handler's printing the error's whole stack to
 *   stderr. A response already ended is left as it is.
 *
 * Every answer carries `Cache-Control: no-store` and `Pragma: no-cache`. The handler never throws:
 * every read of the error is guarded (`guardedRead`), since a throw here would
 * go on to the host's final handler.
 */

import type { ErrorRequestHandler } from "express";
import { auditErrorText, errorEnvelope } from "../errors/envelope.mjs";
import type { Logger } from "../logging/Logger.mjs";
import { guardedRead, loggableError } from "../logging/loggableError.mjs";

/** What a refusal that is the client's mistake is answered with. */
interface CallerMistake {
	/** A 4xx: the parsers' 400, 413 or 415, or another `expose`d refusal's own. */
	readonly status: number;
	readonly description: string;
	/** The one header a 401 or a 405 owes its client, when the refusal carries it. */
	readonly header?: { readonly name: string; readonly value: string };
}

/**
 * body-parser's own types for a body it could not read as sent — JSON or a
 * form it cannot parse, a failed `verify`, a body cut short or longer than
 * declared, a query string nested too deep: `400 malformed_body`.
 */
const MALFORMED_BODY_TYPES: ReadonlySet<unknown> = new Set([
	"entity.parse.failed",
	"entity.verify.failed",
	"request.aborted",
	"request.size.invalid",
	"querystring.parse.rangeError",
]);

/**
 * The decoders' codes for a body that does not decompress, which body-parser
 * passes on untyped: zlib's (`Z_DATA_ERROR`, `Z_BUF_ERROR`) for gzip and
 * deflate, and Node's brotli decoder's format errors
 * (`ERR__ERROR_FORMAT_PADDING_1`, …).
 */
const UNDECOMPRESSIBLE_CODE = /^(?:Z_[A-Z_]+|ERR__ERROR_FORMAT_[A-Z0-9_]+)$/;

/** The header a refusal's status owes its client: a 401's challenge, a 405's methods. */
const OWED_HEADER: Readonly<Record<number, string>> = { 401: "WWW-Authenticate", 405: "Allow" };

/**
 * A header value that can be written as it is: printable ASCII and tab, no
 * line break, and at most {@link HEADER_VALUE_MAX_LENGTH} characters.
 */
const HEADER_VALUE = /^[\t\x20-\x7e]+$/;

/** The longest `WWW-Authenticate` / `Allow` value passed on; a longer one is dropped. */
const HEADER_VALUE_MAX_LENGTH = 1024;

/**
 * The header `status` owes its client, read from the refusal's `http-errors`
 * `headers` (either case of the name) when the value is one a header can
 * hold; nothing else of `headers` is written.
 */
const owedHeader = (
	error: unknown,
	status: number,
): { readonly name: string; readonly value: string } | undefined => {
	const name = OWED_HEADER[status];
	if (name === undefined) return undefined;
	const headers = field(error, "headers");
	const value = field(headers, name) ?? field(headers, name.toLowerCase());
	return typeof value === "string" &&
		value.length <= HEADER_VALUE_MAX_LENGTH &&
		HEADER_VALUE.test(value)
		? { name, value }
		: undefined;
};

/** `error[key]`, or `undefined` when it is not an object or the read throws. */
const field = (error: unknown, key: string): unknown =>
	typeof error === "object" && error !== null ? guardedRead(error, key)?.value : undefined;

/** A path parameter Express 5's router could not decode: a `URIError` it marked `400`. */
const undecodablePath = (error: unknown): boolean => {
	try {
		return error instanceof URIError && field(error, "status") === 400;
	} catch {
		return false;
	}
};

/** The refusal a body parser (or Express's path decoding) raised, as the client's answer; `null` otherwise. */
const callerMistakeOf = (error: unknown): CallerMistake | null => {
	if (undecodablePath(error)) return { status: 400, description: "malformed_path" };
	const expose = field(error, "expose");
	const status = field(error, "status");
	const type = field(error, "type");
	if (expose !== true || !Number.isInteger(status)) return null;
	const answered = status as number;
	if (answered < 400 || answered >= 500) return null;
	if (type === "entity.too.large" || type === "parameters.too.many") {
		return { status: 413, description: "body_too_large" };
	}
	if (type === "charset.unsupported" || type === "encoding.unsupported") {
		return { status: 415, description: "unsupported_encoding" };
	}
	const code = field(error, "code");
	if (
		MALFORMED_BODY_TYPES.has(type) ||
		(type === undefined && typeof code === "string" && UNDECOMPRESSIBLE_CODE.test(code))
	) {
		return { status: 400, description: "malformed_body" };
	}
	const header = owedHeader(error, answered);
	return {
		status: answered,
		description: "request_refused",
		...(header === undefined ? {} : { header }),
	};
};

/**
 * The handler `assembleApp` mounts last on the router it builds, logging on
 * `logger` — the composition's `logger` component, or `consoleLogger`.
 * Exported for a host that mounts routes of its own beside that router (a
 * health check, a metrics scrape): mounted after them, it gives their errors
 * the same answer.
 */
export const terminalErrorHandler =
	(logger: Logger): ErrorRequestHandler =>
	(error, req, res, _next) => {
		const endpoint = auditErrorText(req.path);
		if (res.headersSent) {
			logger.error(
				{ endpoint, headersSent: true, err: loggableError(error) },
				"unhandled_request_error",
			);
			// A response still being written cannot be finished honestly: close
			// it. One already ended is whole — closing now could cut it off
			// before it is flushed, and ends a keep-alive connection for nothing.
			if (!res.writableEnded) req.socket?.destroy();
			return;
		}
		res.setHeader("Cache-Control", "no-store");
		res.setHeader("Pragma", "no-cache");
		const mistake = callerMistakeOf(error);
		if (mistake !== null) {
			if (mistake.header !== undefined) res.setHeader(mistake.header.name, mistake.header.value);
			res.status(mistake.status).json(errorEnvelope("invalid_request", mistake.description));
			return;
		}
		logger.error({ endpoint, err: loggableError(error) }, "unhandled_request_error");
		res.status(500).json(errorEnvelope("server_error", "unexpected_error"));
	};
