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
 * The way to author a `federationTypes` declaration (#728): a helper that ties
 * the factory's entry to the schema.
 *
 * Inside `defineModule({ … })` the `federationTypes` record fixes the entry's
 * type at `unknown` — TypeScript cannot infer a type per key of a record, and
 * the factory is a method, bivariant in its entry — so a schema producing
 * `{ issuer }` would pair with a factory typed for `{ clientId }` unnoticed.
 * The helper infers `E` from `entrySchema` and types the factory's entry with
 * it, checked the strict way (the factory is a property here, not a method).
 * `Deps` is given, not inferred: inside an inferring `defineModule` call a
 * nested call cannot pick the module's deps up, so the declaring module names
 * them (`ProviderDeps<…>`, or the part the factory reads).
 */

import type { z } from "zod";
import type {
	Contributed,
	FederationInstance,
	FederationProvider,
	FederationTypeContribution,
} from "./contributes-map.mjs";

/**
 * A `federationTypes` declaration as the helper takes it: the schema, and a
 * factory whose entry is the schema's output — a function property, so the
 * pairing is checked contravariantly rather than bivariantly.
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
