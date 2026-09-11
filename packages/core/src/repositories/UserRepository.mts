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

import type { User } from "./types.mjs";

/**
 * A federated identity to link to an existing user (#482).
 *
 * `provider:sub` is the whole identity: the federation's name and the IdP's
 * opaque, stable subject. `claims` is what the IdP asserted, as the provider
 * mapped it — `email`, `emailVerified`, `name`, `picture`, and whatever else
 * the adapter surfaces — and it is self-asserted upstream data. The rules a
 * Store must apply before it links (never on an unverified or relay address,
 * never by e-mail alone) are in the session package README.
 */
export interface FederatedIdentityLink {
	/** The federation name — the `:name` route segment, e.g. `"apple"`. */
	readonly provider: string;
	/** The IdP's stable subject identifier for this person. Opaque; never derived from `email`. */
	readonly sub: string;
	/** `<provider>:<sub>` — exactly what `authenticateByToken` will be asked for next time. */
	readonly token: string;
	/** The provider's mapped claims for this login. */
	readonly claims: Readonly<Record<string, unknown>>;
}

/** What the Store answered a link request with (#482). */
export type LinkFederatedIdentityResult =
	| { readonly ok: true; readonly user: User }
	| {
			readonly ok: false;
			/** `conflict`: the identity is already someone else's. `refused`: policy said no. */
			readonly reason: "refused" | "conflict";
			readonly description?: string;
	  };

export interface UserRepository {
	authenticate(username: string, password: string): Promise<User | null>;
	authenticateByToken(token: string): Promise<User | null>;
	/**
	 * Link a federated identity to an existing user (#482). Optional: a Store
	 * that does not implement it makes linking unavailable — the federation
	 * start route refuses `link=1` with `link_unsupported` before sending the
	 * browser anywhere. Called by the federation callback only when the
	 * browser holds an authenticated session for `userId` and the identity
	 * resolves to no user; the Store decides, and answers `refused` (policy)
	 * or `conflict` (the identity is already another account's). Nothing
	 * links implicitly: without `link=1` an unknown identity stays
	 * `unknown_user`.
	 */
	linkFederatedIdentity?(
		userId: string,
		identity: FederatedIdentityLink,
	): Promise<LinkFederatedIdentityResult>;
}

// ---------------------------------------------------------------------------
// ComponentMap slot declaration (per A2-α §6.1)
//
// `userRepository` is a core component produced by a composition-root-local
// module (e.g. `repositoriesModule` in A2-γ §3.8 standalone template). Modules
// that authenticate users (sessionModule's /login, federation routes after
// callback) declare `requires: ["userRepository"]` and receive the instance
// through the typed DI graph.
//
// Per A2-γ §3.4: sessionModule requires userRepository in its manifest.
// ---------------------------------------------------------------------------
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly userRepository: UserRepository;
	}
}
