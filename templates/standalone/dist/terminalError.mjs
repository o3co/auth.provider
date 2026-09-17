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
import { errorEnvelope } from "@o3co/auth-provider-core";
/**
 * Terminal Express error handler (#293 item 8).
 *
 * Anything a route threw past its own try/catch — and every body-parser
 * rejection, which fires before any route runs — used to fall through to
 * Express's default handler: an HTML 500 outside the structured-log pipeline,
 * carrying a stack trace outside production. A client that parses only the
 * RFC 6749 §5.2 JSON envelope this surface answers with everywhere else has
 * no way to read that page.
 *
 * Body-parser failures (malformed JSON/form, over-limit, bad charset) carry
 * their own 4xx `status` and are the client's fault: keep the status, wrap it
 * in the shared envelope, and do not log them as server errors. Everything
 * else is logged with the request path and answered `500 server_error`.
 *
 * Mount it AFTER every route (`app.use(handle.router)` included) — Express
 * routes errors only to handlers registered later.
 */
export const createTerminalErrorHandler = (logger) => {
    return (err, req, res, next) => {
        // A failure after the response started is not ours to rewrite; handing
        // it back lets Express close the connection.
        if (res.headersSent) {
            next(err);
            return;
        }
        const status = err ?? {};
        const httpStatus = typeof status.status === "number"
            ? status.status
            : typeof status.statusCode === "number"
                ? status.statusCode
                : undefined;
        if (httpStatus !== undefined && httpStatus >= 400 && httpStatus < 500) {
            const description = httpStatus === 413 ? "request body too large" : "malformed request body";
            res.status(httpStatus).json(errorEnvelope("invalid_request", description));
            return;
        }
        logger.error({ err, endpoint: req.path }, "unhandled_request_error");
        res.status(500).json(errorEnvelope("server_error", "Internal server error"));
    };
};
