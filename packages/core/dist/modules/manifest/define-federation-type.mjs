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
 * Author a `federationTypes` declaration whose factories' entry is the entry
 * schema's output:
 *
 * ```typescript
 * contributes: {
 *   federationTypes: {
 *     oidc: defineFederationType<OidcModuleDeps>()({
 *       entrySchema: OidcEntry,
 *       factory: (deps, { name, entry }) => createOidcProvider(name, entry), // entry: z.output<typeof OidcEntry>
 *       redirectPolicy: (deps, { entry }) => createRedirectPolicy(entry),
 *     }),
 *   },
 * }
 * ```
 *
 * Curried so that `Deps` is written and `E` inferred. At run time it answers
 * the declaration it was given.
 */
export function defineFederationType() {
    return (declaration) => declaration;
}
