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
import { errorEnvelope, type Logger, loggableError } from "@o3co/auth-provider-core";
import type { ErrorRequestHandler } from "express";

/**
 * Terminal Express error handler (#293 item 8), for the host's own routes.
 *
 * The composed router answers its own errors: core mounts a terminal
 * handler after every route it assembles (`core/src/middleware/terminalError.mts`),
 * so nothing a module's route throws, and no body-parser refusal on one,
 * reaches this handler. What does is an error from the routes `app.mts`
 * mounts beside that router — health, readiness, metrics — which used to fall
 * through to Express's default handler: an HTML 500 outside the
 * structured-log pipeline, carrying a stack trace outside production. A
 * client that parses only the RFC 6749 §5.2 JSON envelope this surface
 * answers with everywhere else has no way to read that page.
 *
 * Body-parser failures (malformed JSON/form, over-limit, bad charset) carry
 * their own 4xx `status` and are the client's fault: keep the status, wrap it
 * in the shared envelope, and do not log them as server errors. Everything
 * else is logged with the request path and answered `500 server_error`.
 *
 * What is logged is core's `loggableError` projection of the error, never
 * the error: an error a route let through can carry what an upstream said —
 * an OAuth library puts the token answer it refused on the cause chain, an
 * ioredis reply the command it answered — and a logger that serialises the
 * error writes all of it out.
 *
 * Mount it AFTER every route (`app.use(handle.router)` included) — Express
 * routes errors only to handlers registered later.
 */
export const createTerminalErrorHandler = (logger: Logger): ErrorRequestHandler => {
	return (err, req, res, next) => {
		// A failure after the response started is not ours to rewrite; handing
		// it back lets Express close the connection.
		if (res.headersSent) {
			next(err);
			return;
		}
		const status = (err as { status?: unknown; statusCode?: unknown } | null) ?? {};
		const httpStatus =
			typeof status.status === "number"
				? status.status
				: typeof status.statusCode === "number"
					? status.statusCode
					: undefined;
		if (httpStatus !== undefined && httpStatus >= 400 && httpStatus < 500) {
			const description = httpStatus === 413 ? "request body too large" : "malformed request body";
			res.status(httpStatus).json(errorEnvelope("invalid_request", description));
			return;
		}
		logger.error({ err: loggableError(err), endpoint: req.path }, "unhandled_request_error");
		res.status(500).json(errorEnvelope("server_error", "Internal server error"));
	};
};
