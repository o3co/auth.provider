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
 * What an operator is told when something failed — and what they are not
 * (#593, D18).
 *
 * Core reports every cause it turns into a typed answer, because a 503 says
 * that something broke without saying what. The error it hands over may be an
 * upstream's, and an upstream's error carries whatever the upstream echoed
 * back: a request body, a refresh token it did not like, a header. The same
 * is true of the errors the shared client-authentication and rate-limit
 * middleware log when a repository throws.
 *
 * So both of these are built from an **allowlist**, not by redacting the
 * error. A redaction list is a list of the leaks somebody has already thought
 * of, and this is exactly the code path where the thing nobody thought of
 * arrives from another system.
 */

import type { AuditSink, Logger } from "@o3co/auth-provider-core";

/**
 * The closed set a failure is described by.
 *
 * Derived from an error's `name` only where the name is one of these. A name
 * is a writable string on an ordinary object, and an error built from a
 * parsed upstream response carries whatever that response said — so an
 * unrecognised one becomes `unknown` rather than being passed through.
 */
const CLASSIFICATIONS: ReadonlyMap<string, string> = new Map([
	["AbortError", "aborted"],
	["TimeoutError", "timeout"],
	["TypeError", "type_error"],
	["RangeError", "range_error"],
	["SyntaxError", "syntax_error"],
]);

const classify = (error: unknown): string => {
	if (error instanceof Error) return CLASSIFICATIONS.get(error.name) ?? "unknown";
	return "unknown";
};

/**
 * The `report` seam of `RetrieveFederationGrantTokenDeps`.
 *
 * Four fields and a classification, and nothing that came out of the error
 * itself. What makes it useful is the correlation: the same `x-request-id` the
 * caller was answered under, including for a refresh that failed after the
 * answer was sent.
 */
/**
 * What a failure report carries — core's `FederationGrantRetrievalFailure`
 * with `during` widened to a plain string.
 *
 * Widened here rather than in core so the route can report its own unexpected
 * failures through the same function: a handler that threw did not fail
 * *during* any of core's phases, and inventing a core phase for it would put a
 * lie in an operator's logs. A function taking this is still assignable to
 * core's narrower `report` seam.
 */
export interface SanitizedFailure {
	readonly during: string;
	readonly error: unknown;
	readonly grantId: string;
	readonly correlationId: string;
}

export function createSanitizedReporter(logger: Logger): (failure: SanitizedFailure) => void {
	return (failure) => {
		logger.warn(
			{
				event: "federation_grant.failure",
				during: failure.during,
				grantId: failure.grantId,
				correlationId: failure.correlationId,
				classification: classify(failure.error),
			},
			"federation grant operation failed",
		);
	};
}

const scalar = (value: unknown): value is string | number | boolean =>
	typeof value === "string" || typeof value === "number" || typeof value === "boolean";

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
const SAFE_FIELDS: ReadonlySet<string> = new Set([
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

const sanitizePayload = (payload: Record<string, unknown>): Record<string, unknown> => {
	const safe: Record<string, unknown> = {};
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
export function createSanitizedAuditSink(sink: AuditSink): AuditSink {
	return {
		kind: sink.kind,
		record: (event) =>
			sink.record({
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
export function createSanitizedLogger(logger: Logger): Logger {
	const level =
		(name: "trace" | "debug" | "info" | "warn" | "error" | "fatal") =>
		(first: Record<string, unknown> | string, ...rest: unknown[]): void => {
			if (typeof first === "string") {
				// Printf-style: the message is the call site's own literal, and
				// the trailing arguments are what a legacy site passed an error
				// as — dropped rather than forwarded.
				logger[name](first);
				return;
			}
			const [msg] = rest;
			if (typeof msg === "string") logger[name](sanitizePayload(first), msg);
			else logger[name](sanitizePayload(first));
		};
	return {
		trace: level("trace"),
		debug: level("debug"),
		info: level("info"),
		warn: level("warn"),
		error: level("error"),
		fatal: level("fatal"),
		child: (bindings) => createSanitizedLogger(logger.child(sanitizePayload(bindings))),
	} as Logger;
}
