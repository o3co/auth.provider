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

export interface UserRepository {
	authenticate(username: string, password: string): Promise<User | null>;
	authenticateByToken(token: string): Promise<User | null>;
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
