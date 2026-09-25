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
 *   cannot decode `415 unsupported_encoding`, anything else it refused (JSON
 *   it cannot read, a body that does not decompress) `400 malformed_body`. A
 *   path parameter Express could not decode is `400 malformed_path`. Only
 *   `expose`, `status` and `type` are read, never the message, which quotes
 *   the body. It is the same reading as those two routers' `parserRefusals`;
 *   at this position an `expose`d 4xx from elsewhere is read the same way,
 *   which is what `expose` says of an `http-errors` error.
 * - Anything else is `500 server_error` (`unexpected_error`), logged once at
 *   error as `unhandled_request_error` with `endpoint` (the path, through
 *   `auditErrorText`) and the error's `loggableError` projection — never the
 *   error, whose fields can carry what a store or a peer said.
 * - A response whose headers already went out cannot be answered: it is
 *   logged the same way, with `headersSent: true`, and its connection closed,
 *   as Express's final handler would close it — without the final handler's
 *   printing the error's whole stack to stderr.
 *
 * Every answer carries `Cache-Control: no-store`. The handler never throws:
 * every read of the error is guarded (`guardedRead`), since a throw here would
 * go on to the host's final handler.
 */

import type { ErrorRequestHandler } from "express";
import { auditErrorText, errorEnvelope } from "../errors/envelope.mjs";
import type { Logger } from "../logging/Logger.mjs";
import { guardedRead, loggableError } from "../logging/loggableError.mjs";

/** What a refusal that is the client's mistake is answered with. */
interface CallerMistake {
	readonly status: 400 | 413 | 415;
	readonly description: string;
}

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
	if (expose !== true || typeof status !== "number" || status < 400 || status >= 500) return null;
	if (type === "entity.too.large" || type === "parameters.too.many") {
		return { status: 413, description: "body_too_large" };
	}
	if (type === "charset.unsupported" || type === "encoding.unsupported") {
		return { status: 415, description: "unsupported_encoding" };
	}
	return { status: 400, description: "malformed_body" };
};

/**
 * The handler `assembleApp` mounts last on the router it builds, logging on
 * `logger` — the composition's `logger` component, or `consoleLogger`.
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
			req.socket?.destroy();
			return;
		}
		res.setHeader("Cache-Control", "no-store");
		const mistake = callerMistakeOf(error);
		if (mistake !== null) {
			res.status(mistake.status).json(errorEnvelope("invalid_request", mistake.description));
			return;
		}
		logger.error({ endpoint, err: loggableError(error) }, "unhandled_request_error");
		res.status(500).json(errorEnvelope("server_error", "unexpected_error"));
	};
