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
 * What a `client_id` from a request must look like before a
 * {@link ClientRepository} is asked for it, and what a registered one must
 * look like for a request to be able to name it.
 *
 * A malformed `client_id` must not make a repository throw (a SQL driver
 * refuses a NUL byte, an HTTP store an overlong URL): a throw is answered
 * `503`, and the client's input would read as the server's outage. Routes
 * refuse a malformed id like an unknown one, without a lookup, and the
 * bundled repository refuses to register one. The rule is core's identifier
 * rule (`security/identifier.mts`).
 *
 * @see ClientRepository
 */

import {
	describeMalformedIdentifier,
	isWellFormedIdentifier,
	MAX_IDENTIFIER_LENGTH,
} from "../security/identifier.mjs";

/**
 * The longest `client_id` a repository is asked for: 256 characters. RFC 6749
 * bounds nothing; registered ids and Client ID Metadata Document URLs are far
 * shorter in practice, and a longer metadata-document URL is not a client id
 * this server honours, at `/authorize` or at the token endpoint.
 *
 * Not a column size: `VARCHAR(255)` holds one character fewer. A repository
 * whose store fails on a 256-character id, rather than finding no row, must
 * answer that id `null` itself: only a store that cannot answer may throw.
 */
export const MAX_CLIENT_ID_LENGTH = MAX_IDENTIFIER_LENGTH;

/** Whether `clientId` can name a client (see the module comment). */
export function isWellFormedClientId(clientId: unknown): clientId is string {
	return isWellFormedIdentifier(clientId);
}

/**
 * Refuses a set of registered client ids any of which no request could name.
 * The error names the entry's position (1-based, in registration order) and
 * what is wrong — never the id itself, which may carry control characters.
 */
export function assertRegistrableClientIds(owner: string, clientIds: Iterable<unknown>): void {
	let position = 0;
	for (const clientId of clientIds) {
		position += 1;
		if (!isWellFormedClientId(clientId)) {
			throw new Error(
				`${owner}: the client registered at position ${position} has a client_id no request ` +
					`can name (${describeMalformedIdentifier(clientId)}). A client_id must be a string of 1 ` +
					`to ${MAX_CLIENT_ID_LENGTH} characters with no control character: every route refuses ` +
					"any other as an unknown client, so this registration could never be used.",
			);
		}
	}
}
