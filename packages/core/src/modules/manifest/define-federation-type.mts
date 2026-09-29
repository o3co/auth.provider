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
 * The way to author a `federationTypes` declaration: a helper that ties the
 * factory's entry to the schema.
 *
 * Inside `defineModule({ … })` the record fixes the entry at `unknown` (no
 * per-key inference, and a method is bivariant in its entry), so a schema for
 * `{ issuer }` could pair with a factory typed for `{ clientId }` unnoticed.
 * The helper infers `E` from `entrySchema` and checks the factory, a property
 * here, strictly. `Deps` is written, not inferred: a nested call inside an
 * inferring `defineModule` cannot pick up the module's deps.
 */

import type { z } from "zod";
import type {
	Contributed,
	FederationInstance,
	FederationProvider,
	FederationTypeContribution,
} from "./contributes-map.mjs";

/**
 * A `federationTypes` declaration as the helper takes it. The factory is a
 * function property, so its pairing with the schema is checked contravariantly.
 */
export interface FederationTypeDeclaration<Deps, E> {
	readonly entrySchema: z.ZodType<E>;
	readonly factory: (
		deps: Deps,
		instance: FederationInstance<E>,
	) => Contributed<FederationProvider>;
}

/**
 * Author a `federationTypes` declaration whose factory's entry is the entry
 * schema's output:
 *
 * ```typescript
 * contributes: {
 *   federationTypes: {
 *     oidc: defineFederationType<OidcModuleDeps>()({
 *       entrySchema: OidcEntry,
 *       factory: (deps, { name, entry }) => createOidcProvider(name, entry), // entry: z.output<typeof OidcEntry>
 *     }),
 *   },
 * }
 * ```
 *
 * Curried so that `Deps` is written and `E` inferred. At run time it answers
 * the declaration it was given.
 */
export function defineFederationType<Deps>(): <E>(
	declaration: FederationTypeDeclaration<Deps, E>,
) => FederationTypeContribution<Deps, E> {
	return (declaration) => declaration;
}
