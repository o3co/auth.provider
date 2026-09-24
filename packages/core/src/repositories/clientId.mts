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
 * {@link ClientRepository} is asked for it.
 *
 * A repository throws only when its store cannot answer, and that is answered
 * `503`. A client's malformed `client_id` must not be able to make one throw:
 * a SQL driver refuses a NUL byte, an HTTP store refuses a URL too long for
 * it — and the client's input would read as the server's outage. So the
 * routes that look a client up screen the id first and refuse a malformed one
 * the way they refuse an unknown one.
 *
 * - No control character — C0 (`U+0000`–`U+001F`), DEL (`U+007F`), C1
 *   (`U+0080`–`U+009F`). RFC 6749 Appendix A.1 makes `client_id` `*VSCHAR`
 *   (printable ASCII), so no control character can be part of one; the rule
 *   stops short of refusing all non-ASCII, which a registry may already hold.
 * - At most {@link MAX_CLIENT_ID_LENGTH} characters, and not empty.
 *
 * @see ClientRepository
 */

/**
 * The longest `client_id` a repository is asked for. RFC 6749 bounds nothing;
 * a registered client id is an operator-chosen identifier, and a Client ID
 * Metadata Document's is an `https` URL that names a document — both far
 * shorter in practice. 256 characters is past both, and is the size of the
 * identifier column a SQL-backed repository most often has (`VARCHAR(255)`
 * and its neighbours), so a well-formed id is one such a store can always
 * take. A Client ID Metadata Document URL longer than this is not a client id
 * this server honours, at `/authorize` or at the token endpoint.
 */
export const MAX_CLIENT_ID_LENGTH = 256;

// biome-ignore lint/suspicious/noControlCharactersInRegex: finding control characters is the point of this check.
const CONTROL_CHARACTER = /[\u0000-\u001f\u007f-\u009f]/;

/** Whether `clientId` can name a client (see the module comment). */
export function isWellFormedClientId(clientId: unknown): clientId is string {
	return (
		typeof clientId === "string" &&
		clientId.length > 0 &&
		clientId.length <= MAX_CLIENT_ID_LENGTH &&
		!CONTROL_CHARACTER.test(clientId)
	);
}
