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

import type { Client } from "./types.mjs";

export type PublicClient = Omit<Client, "clientSecret">;

/**
 * Where OAuth clients are looked up.
 *
 * The contract every route relies on:
 *
 * - An unknown client or a non-matching secret is `null`, never a throw:
 *   the client's fault, answered `invalid_client`.
 * - Throw only when the store cannot answer. Client authentication (the
 *   oauth package's `createClientAuthMiddleware`) and `/authorize` answer a
 *   throw as `503 temporarily_unavailable` and log it at error level as
 *   `client_repository_unavailable`, so throwing for a client's mistake
 *   turns it into the server's outage.
 * - The `clientId` is client input. Those routes refuse a malformed one
 *   (`isWellFormedClientId`) before asking the repository, but any other
 *   character may still be in it: bind it as a query parameter, never
 *   interpolate it.
 * - Core's boundary (`validatedClientRepository`) reads a record answered
 *   once, by name, and holds it to the registration's rules; a record it
 *   refuses is an unknown client, and its `lookupClient` tells that refusal
 *   from an absent record.
 */
export interface ClientRepository {
	/**
	 * Look up a client without authentication. Returns the client's public
	 * fields (everything except `clientSecret`) or `null` when the client does
	 * not exist. Used by `clientAuthMw` for the public-client (`tokenEndpoint-
	 * AuthMethod === "none"`) path and by `/authorize` for redirect-URI /
	 * scope validation.
	 *
	 * Naming convention: `findBy<Field>` for key lookups returning a public
	 * projection without authentication; single-object stores (e.g.
	 * `UserSessionStore`) use `get(<id>)`; operation names like
	 * `consumeByCode` mark atomic single-use and are outside the convention.
	 */
	findById(clientId: string): Promise<PublicClient | null>;
	/**
	 * Authenticate a confidential client by `clientId` + secret pair. Returns
	 * the public projection on success, `null` when the client does not exist
	 * or the secret does not match. Implementations MUST return `null` (and
	 * SHOULD NOT throw) when called for a `tokenEndpointAuthMethod === "none"`
	 * client — public clients have no secret to authenticate against, and
	 * accepting any string would silently promote them to confidential.
	 */
	authenticate(clientId: string, secret: string): Promise<PublicClient | null>;
}

// ---------------------------------------------------------------------------
// ComponentMap slot declaration
//
// `clientRepository` is produced by a composition-root-local module (e.g. the
// standalone template's `repositoriesModule`). Modules that validate OAuth
// clients declare `requires: ["clientRepository"]`.
// ---------------------------------------------------------------------------
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly clientRepository: ClientRepository;
	}
}
