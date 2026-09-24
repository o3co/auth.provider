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
 * What an audit event may carry of an error.
 *
 * An audit sink is a record other systems read — a SIEM, a dashboard, a
 * compliance archive — and a deployment chooses it. A store's or an IdP's
 * error message is peer-written text: the arguments a Redis reply quotes
 * (a token among them), the input a JSON parser choked on, an upstream's own
 * description. `loggableError` decides what a log line may keep of that; an
 * audit event keeps less, because it is kept longer and read by more.
 */

import { auditErrorText } from "../errors/envelope.mjs";
import { type LoggableError, loggableError } from "../logging/loggableError.mjs";

/**
 * An error as an audit event's `details.cause` carries it: the name and the
 * code `loggableError` reads, each sanitised and capped as
 * {@link auditErrorText} does, one level of its cause the same way, and never
 * a message.
 *
 * Every field keeps one type in every event — a numeric code is written as a
 * string — because a sink that fixes a field's type the first time it sees it
 * (Elasticsearch dynamic mapping, a BigQuery schema, a Datadog facet) drops
 * the events that disagree.
 */
export interface AuditedError {
	/** The error's `name`; `"NonError"` for a thrown value that is not an Error. */
	readonly name: string;
	/** A library's or a store's code, e.g. `ECONNREFUSED` or `OAUTH_RESPONSE_BODY_ERROR`. */
	readonly code?: string;
	/**
	 * The error's own cause, one level: undici's `fetch failed` is a
	 * `TypeError` whose cause holds the `ECONNREFUSED`.
	 */
	readonly cause?: AuditedErrorCause;
}

/** An {@link AuditedError}'s cause: the name and code, and no further cause. */
export interface AuditedErrorCause {
	readonly name: string;
	readonly code?: string;
}

/**
 * The {@link AuditedError} of `err`, for an audit event's `details.cause`:
 * what kind of error it was and what caused it, bounded, and nothing a peer
 * wrote into either.
 */
export function auditedError(err: unknown): AuditedError {
	const projected = loggableError(err);
	return {
		...nameAndCode(projected),
		...(projected.cause !== undefined ? { cause: nameAndCode(projected.cause) } : {}),
	};
}

function nameAndCode({ name, code }: LoggableError): AuditedErrorCause {
	return {
		name: auditErrorText(name),
		...(code !== undefined ? { code: auditErrorText(String(code)) } : {}),
	};
}
