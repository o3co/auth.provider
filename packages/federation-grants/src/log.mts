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
 * Every line this package writes (README, "What is logged"), in the three
 * kinds {@link FederationGrantLog} names: an outage, a failure that changed no
 * answer, and what escaped a handler.
 *
 * Every line is object-first with an event name as its message and nothing
 * after it: pino drops what follows a string. A caught error goes on it as
 * `err`, core's `loggableError` projection and never the error: the projection
 * is the redaction. Every string field is sanitised and capped
 * (`auditErrorText`): a grant id, a connection or a client id can be what the
 * caller sent.
 */

import {
	auditErrorText,
	consoleLogger,
	type Logger,
	logClientRepositoryUnavailable,
	loggableError,
} from "@o3co/auth-provider-core";

/**
 * What a line carries beside its error: scalars only, so that no caller can
 * hand an error — or anything carrying one — to the logger past the
 * projection. `undefined` leaves the field out.
 */
export type LogFields = Readonly<Record<string, string | number | boolean | undefined>>;

/**
 * The cause of a line, when it has one: `[error]`, or nothing. A rest tuple
 * rather than an optional parameter, so that a thrown `undefined` is still a
 * cause the line projects.
 */
type Cause = [] | [error: unknown];

export interface FederationGrantLog {
	/** An outage answered `503` or `temporarily_unavailable`: exactly one line, at error. */
	outage(event: string, fields: LogFields, ...cause: Cause): void;
	/** A failure that changed no answer, or contention: one line, at warn. */
	degraded(event: string, fields: LogFields, ...cause: Cause): void;
	/**
	 * What escaped a handler: `federation_grants_unexpected_error`, at error,
	 * with `site` — the handler that caught it, or the router whose last error
	 * handler did.
	 */
	unexpected(site: string, fields: LogFields, error: unknown): void;
	/** A client lookup that could not be made: core's `client_repository_unavailable`, at error. */
	clientRepositoryUnavailable(site: string, clientId: unknown, error: unknown): void;
	/**
	 * The logger with `fields` bound to every line it writes, sanitised and
	 * capped as a line's own: for a caller that writes its own lines through
	 * core — session admission, whose outage line then carries the grant and
	 * the request's correlation id.
	 */
	bound(fields: LogFields): Logger;
}

/** The line: every string sanitised and capped, `undefined` left out, the cause projected. */
function payload(fields: LogFields, cause: Cause): Record<string, unknown> {
	const line: Record<string, unknown> = {};
	for (const [key, value] of Object.entries(fields)) {
		if (value === undefined) continue;
		line[key] = typeof value === "string" ? auditErrorText(value) : value;
	}
	if (cause.length > 0) line.err = loggableError(cause[0]);
	return line;
}

/** The lines of one router, through the deployment's logger; the console's when it has none. */
export function createFederationGrantLog(given: Logger | undefined): FederationGrantLog {
	const logger = given ?? consoleLogger;
	return {
		outage: (event, fields, ...cause) => logger.error(payload(fields, cause), event),
		degraded: (event, fields, ...cause) => logger.warn(payload(fields, cause), event),
		unexpected: (site, fields, error) =>
			logger.error(payload({ site, ...fields }, [error]), "federation_grants_unexpected_error"),
		clientRepositoryUnavailable: (site, clientId, error) =>
			logClientRepositoryUnavailable(logger, { site, step: "find", clientId }, error),
		bound: (fields) => logger.child(payload(fields, [])),
	};
}

/**
 * `error[key]`, or `undefined` when the read throws — a getter, a Proxy's
 * trap, or `null` / `undefined`, which have nothing to read. A primitive's
 * own properties are read as any value's: none holds `expose`, `status` or
 * `type`. What classifies an error must never throw on it: a throw in the
 * routers' last error handler reaches Express's own, which answers HTML and
 * logs nothing of this package's.
 */
export const readField = (error: unknown, key: string): unknown => {
	try {
		return (error as Record<string, unknown>)[key];
	} catch {
		return undefined;
	}
};

/** `error instanceof type`, or `false` when asking throws (a Proxy whose prototype cannot be read). */
export const isInstance = (
	error: unknown,
	type: abstract new (...args: never[]) => unknown,
): boolean => {
	try {
		return error instanceof type;
	} catch {
		return false;
	}
};
