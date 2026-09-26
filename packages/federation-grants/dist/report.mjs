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
 * The closed set a failure is described by.
 *
 * Derived from an error's `name` only where the name is one of these. A name
 * is a writable string on an ordinary object, and an error built from a
 * parsed upstream response carries whatever that response said — so an
 * unrecognised one becomes `unknown` rather than being passed through.
 */
const CLASSIFICATIONS = new Map([
    ["AbortError", "aborted"],
    ["TimeoutError", "timeout"],
    ["TypeError", "type_error"],
    ["RangeError", "range_error"],
    ["SyntaxError", "syntax_error"],
]);
const classify = (error) => {
    if (error instanceof Error)
        return CLASSIFICATIONS.get(error.name) ?? "unknown";
    return "unknown";
};
export function createSanitizedReporter(logger) {
    return (failure) => {
        logger.warn({
            event: "federation_grant.failure",
            during: failure.during,
            grantId: failure.grantId,
            correlationId: failure.correlationId,
            classification: classify(failure.error),
        }, "federation grant operation failed");
    };
}
const scalar = (value) => typeof value === "string" || typeof value === "number" || typeof value === "boolean";
/**
 * The field NAMES this package will carry, and nothing else.
 *
 * It was a type check first — scalars through, objects redacted — and review
 * found the hole: `checkWithFailMode` turns a limiter's exception into its
 * `message` and logs `{ error: <that string>, … }`, so a driver that names a
 * connection string in its error passed straight through as a perfectly
 * ordinary string. A repository that throws a string does the same. **What a
 * value's TYPE is says nothing about where it came from**, which is the whole
 * argument for an allowlist, and this is now one.
 *
 * Adding a field here means deciding that this route may carry it. A field
 * left out is redacted, not dropped: an operator can still see that there was
 * one.
 */
const SAFE_FIELDS = new Set([
    // This package's own reports.
    "event",
    "during",
    "grantId",
    "correlationId",
    "classification",
    // What the shared middleware logs beside its errors.
    "tag",
    "mode",
    "ip",
    "clientId",
    "method",
    "path",
    "status",
    "limit",
    "remaining",
    "operation",
]);
const sanitizePayload = (payload) => {
    const safe = {};
    for (const [key, value] of Object.entries(payload)) {
        safe[key] = SAFE_FIELDS.has(key) && scalar(value) ? value : "[redacted]";
    }
    return safe;
};
/**
 * The audit sink handed to the shared rate-limit guard.
 *
 * Its `rate_limit.unavailable` event carries `details.error` — the same
 * stringified limiter exception the log line carries — so the sink needs the
 * same allowlist the logger does. The event itself is kept: an operator's
 * dashboard counts limiter outages, and the count is the useful part.
 */
export function createSanitizedAuditSink(sink) {
    return {
        kind: sink.kind,
        record: (event) => sink.record({
            ...event,
            ...(event.details === undefined ? {} : { details: sanitizePayload(event.details) }),
        }),
    };
}
/**
 * A {@link Logger} facade handed to the shared middleware this package mounts.
 *
 * `createClientAuthMiddleware` and the rate-limit guard log a repository
 * failure with the raw error among the structured fields. That is right for a
 * deployment that has decided what its logger redacts; it is not something
 * this route can decide for it, and this is the one route whose repository
 * errors can arrive from an upstream IdP. So the middleware is given this
 * instead of the deployment's own logger: object-first calls keep their
 * scalars and lose everything else, string-first calls pass through.
 */
export function createSanitizedLogger(logger) {
    const level = (name) => (first, ...rest) => {
        if (typeof first === "string") {
            // Printf-style: the message is the call site's own literal, and
            // the trailing arguments are what a legacy site passed an error
            // as — dropped rather than forwarded.
            logger[name](first);
            return;
        }
        const [msg] = rest;
        if (typeof msg === "string")
            logger[name](sanitizePayload(first), msg);
        else
            logger[name](sanitizePayload(first));
    };
    return {
        trace: level("trace"),
        debug: level("debug"),
        info: level("info"),
        warn: level("warn"),
        error: level("error"),
        fatal: level("fatal"),
        child: (bindings) => createSanitizedLogger(logger.child(sanitizePayload(bindings))),
    };
}
