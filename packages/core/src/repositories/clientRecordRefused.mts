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
 * The refusal a client-record boundary rejects a lookup with when the
 * repository answered a record the registration rules refuse.
 *
 * - **Recognised by its brand alone.** The brand is a global symbol
 *   (`Symbol.for`), held on the refusal itself, so a refusal built by another
 *   loaded copy of core reads the same. `instanceof` is never the test, and a
 *   wrapper around a refusal (an Error whose `cause` is one) is not one.
 * - **It carries nothing of the record.** No client id, no reason, no URI:
 *   the boundary's own `client_record_refused` warn says what was refused
 *   and why. Its own `reason` is the code a log line's error projection keeps
 *   (`loggableError`), so an outage line written for it names its cause.
 * - **Frozen**, so no layer it passes through can rewrite it. A consumer
 *   never annotates it (`err.status = …` throws in strict mode): it passes
 *   the refusal on as it is, or wraps it as a new error's `cause`.
 */

/** The global brand a client-record refusal carries on itself. */
const CLIENT_RECORD_REFUSED = Symbol.for("@o3co/auth-provider-core/client-record-refused");

/** The rejection of a lookup whose record a client-record boundary refused. */
export class ClientRecordRefusedError extends Error {
	/** The cause, as a code: what a log line's error projection keeps. */
	readonly reason = "client_record_refused";

	constructor() {
		super("the client's registered record was refused by the client-record boundary");
		this.name = "ClientRecordRefusedError";
		Object.defineProperty(this, CLIENT_RECORD_REFUSED, { value: true });
		Object.freeze(this);
	}
}

/**
 * Whether `value` is a client-record refusal: an object carrying the brand
 * on itself, whichever constructor built it. Never throws: a value whose
 * read throws is not a refusal.
 */
export function isClientRecordRefused(value: unknown): boolean {
	if (typeof value !== "object" || value === null) return false;
	try {
		return (
			Object.hasOwn(value, CLIENT_RECORD_REFUSED) &&
			(value as Record<symbol, unknown>)[CLIENT_RECORD_REFUSED] === true
		);
	} catch {
		return false;
	}
}
