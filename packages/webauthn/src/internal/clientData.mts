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
 * The one reading of a response's client data outside `@simplewebauthn/server`'s verification:
 * with the library's own decoder, so a field read here is read from the text the library
 * verifies, base64url canonical or not. Not exported from the package barrel.
 */

import { decodeClientDataJSON } from "@simplewebauthn/server/helpers";

/**
 * `clientDataJSON` decoded as the library decodes it, or `undefined` when that is not a JSON
 * object.
 */
export function readClientData(
	clientDataJSON: string,
): Readonly<Record<string, unknown>> | undefined {
	let clientData: unknown;
	try {
		clientData = decodeClientDataJSON(clientDataJSON);
	} catch {
		return undefined;
	}
	return typeof clientData === "object" && clientData !== null
		? (clientData as Readonly<Record<string, unknown>>)
		: undefined;
}
