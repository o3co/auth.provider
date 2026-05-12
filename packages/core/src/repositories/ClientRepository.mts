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

export interface ClientRepository {
	/**
	 * Look up a client without authentication. Returns the client's public
	 * fields (everything except `clientSecret`) or `null` when the client does
	 * not exist. Used by `clientAuthMw` for the public-client (`tokenEndpoint-
	 * AuthMethod === "none"`) path and by `/authorize` for redirect-URI /
	 * scope validation that does not require credential authentication.
	 *
	 * Naming convention (AS-10, since v0.5.1): repositories use
	 * `findBy<Field>` for primary-key and alternate-key lookups returning
	 * a public projection without authentication. Single-object stores
	 * (e.g. `UserSessionStore`) use `get(<id>)` instead. Operation-specific
	 * names like `consumeByCode` denote atomic single-use semantics; they
	 * are NOT subject to the `findBy` convention. The convention is
	 * currently enforced by code review on PRs that add or rename
	 * repository methods; a lint rule and contributor-guide section may
	 * follow once the convention has settled across all repositories.
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
// ComponentMap slot declaration (per A2-α §6.1)
//
// `clientRepository` is a core component produced by a composition-root-local
// module (e.g. `repositoriesModule` in A2-γ §3.8 standalone template). Modules
// that validate OAuth clients declare `requires: ["clientRepository"]` and
// receive the instance through the typed DI graph.
//
// Per A2-γ §3.2.3 / §3.2.2 / §3.2.1: oauthSessionModule, oauthAuthorization-
// Module, and oauthModule all require clientRepository in their manifests.
// ---------------------------------------------------------------------------
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly clientRepository: ClientRepository;
	}
}
