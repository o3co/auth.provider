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

import type { Code } from "./types.mjs";

export interface CodeRepository {
	/**
	 * Issue an authorization code and persist all associated data atomically.
	 * After `consumeByCode`, the code is single-use; `client_id` and
	 * `redirect_uri` embedded in the record replace the session-based identity
	 * binding removed in v0.5.1 (D-1 spec).
	 */
	createCode(params: {
		client_id: string; // required (D-1)
		redirect_uri: string; // required (D-1)
		code_challenge?: string;
		code_challenge_method?: string;
		expiresIn?: number;
		grantedScope?: readonly string[];
		grantedAudience?: readonly string[];
		// NEW (TODO-F-3): OIDC authorize → token round-trip state.
		nonce?: string;
		sid?: string;
	}): Promise<Code>;
	/**
	 * Retrieve a code record by the authorization code string. Returns
	 * `null` when no record matches — the method is fail-soft on absence,
	 * matching the `findBy<Field>` convention used by
	 * `ClientRepository.findById`.
	 *
	 * Naming note (AS-10): renamed from `getByCode` to `findByCode` at 1.0
	 * GA to align with the repository-method convention introduced in
	 * v0.5.1: `findBy<Field>` for optional lookups (`null` on absence),
	 * `get(<id>)` for single-object stores, and operation-specific names
	 * like `consumeByCode` (atomic single-use) for non-lookup operations.
	 * The v0.5.x `getByCode` name was deprecated via the JSDoc-only
	 * documentation in v0.5.2 (AS-10).
	 */
	findByCode(code: string): Promise<Code | null>;
	/**
	 * Atomically retrieve and delete the code record. This is the sole
	 * authenticity gate for authorization code exchange. Returns null when the
	 * code is unknown or has already been consumed (replay prevention).
	 */
	consumeByCode(code: string): Promise<Code | null>;
	removeByCode(code: string): Promise<void>;
}

// ---------------------------------------------------------------------------
// ComponentMap slot declaration (per A2-α §6.1)
//
// `codeRepository` is a core component produced by a composition-root-local
// module (e.g. `repositoriesModule` in A2-γ §3.8 standalone template). Modules
// that issue or exchange authorization codes declare `requires: ["codeRepository"]`
// and receive the instance through the typed DI graph.
//
// Per A2-γ §3.2.2: oauthAuthorizationModule requires codeRepository in its
// manifest to pass it into createAuthorizationGrant.
// ---------------------------------------------------------------------------
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly codeRepository: CodeRepository;
	}
}
