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
import { auditErrorText, errorEnvelope } from "../errors/envelope.mjs";
import { guardedRead, loggableError } from "../logging/loggableError.mjs";
/**
 * body-parser's own types for a body it could not read as sent — JSON or a
 * form it cannot parse, a failed `verify`, a body cut short or longer than
 * declared, a query string nested too deep: `400 malformed_body`.
 */
const MALFORMED_BODY_TYPES = new Set([
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
const OWED_HEADER = { 401: "WWW-Authenticate", 405: "Allow" };
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
const owedHeader = (error, status) => {
    const name = OWED_HEADER[status];
    if (name === undefined)
        return undefined;
    const headers = field(error, "headers");
    const value = field(headers, name) ?? field(headers, name.toLowerCase());
    return typeof value === "string" &&
        value.length <= HEADER_VALUE_MAX_LENGTH &&
        HEADER_VALUE.test(value)
        ? { name, value }
        : undefined;
};
/** `error[key]`, or `undefined` when it is not an object or the read throws. */
const field = (error, key) => typeof error === "object" && error !== null ? guardedRead(error, key)?.value : undefined;
/** A path parameter Express 5's router could not decode: a `URIError` it marked `400`. */
const undecodablePath = (error) => {
    try {
        return error instanceof URIError && field(error, "status") === 400;
    }
    catch {
        return false;
    }
};
/** The refusal a body parser (or Express's path decoding) raised, as the client's answer; `null` otherwise. */
const callerMistakeOf = (error) => {
    if (undecodablePath(error))
        return { status: 400, description: "malformed_path" };
    const expose = field(error, "expose");
    const status = field(error, "status");
    const type = field(error, "type");
    if (expose !== true || !Number.isInteger(status))
        return null;
    const answered = status;
    if (answered < 400 || answered >= 500)
        return null;
    if (type === "entity.too.large" || type === "parameters.too.many") {
        return { status: 413, description: "body_too_large" };
    }
    if (type === "charset.unsupported" || type === "encoding.unsupported") {
        return { status: 415, description: "unsupported_encoding" };
    }
    const code = field(error, "code");
    if (MALFORMED_BODY_TYPES.has(type) ||
        (type === undefined && typeof code === "string" && UNDECOMPRESSIBLE_CODE.test(code))) {
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
export const terminalErrorHandler = (logger) => (error, req, res, _next) => {
    const endpoint = auditErrorText(req.path);
    if (res.headersSent) {
        logger.error({ endpoint, headersSent: true, err: loggableError(error) }, "unhandled_request_error");
        // A response still being written cannot be finished honestly: close
        // it. One already ended is whole — closing now could cut it off
        // before it is flushed, and ends a keep-alive connection for nothing.
        if (!res.writableEnded)
            req.socket?.destroy();
        return;
    }
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("Pragma", "no-cache");
    const mistake = callerMistakeOf(error);
    if (mistake !== null) {
        if (mistake.header !== undefined)
            res.setHeader(mistake.header.name, mistake.header.value);
        res.status(mistake.status).json(errorEnvelope("invalid_request", mistake.description));
        return;
    }
    logger.error({ endpoint, err: loggableError(error) }, "unhandled_request_error");
    res.status(500).json(errorEnvelope("server_error", "unexpected_error"));
};
