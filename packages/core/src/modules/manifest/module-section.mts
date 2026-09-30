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
 * A module's own configuration section: the manifest declares the schema of
 * the one section it owns, and every factory of the module receives that
 * section parsed, as `deps.section`, instead of reading the whole config.
 *
 * Target shape: a top-level kebab-case section named after exactly one module
 * (`device-grant {}`), camelCase keys, defaults only in the owning package's
 * `config/reference.conf`, and no module reading another's section. `at` and
 * `relocatedFrom` bridge sections that have not moved there yet.
 */

import type { z } from "zod";

/**
 * The schema a module's section is parsed with: any Zod schema. It is the
 * widest one, so `Module` — the erased manifest boot takes — is written with
 * it, and any sectioned manifest is assignable to `Module`.
 */
export type SectionSchema = z.ZodType;

/**
 * A `relocatedFrom` map entry whose new path — `to`, inside the section as a
 * string entry is — no environment variable binds: a key moved there is
 * refused naming none.
 */
export interface RelocationWithoutVariable {
	readonly to: string;
	readonly environmentVariable: null;
}

/**
 * The `section` field of a manifest: the module's own configuration section.
 *
 * At stage 1, before any factory runs, boot reads the value at {@link at},
 * parses it synchronously with {@link schema}, and hands the result to every
 * factory of the module as `deps.section`: one deeply frozen object (plain
 * data copied; other values as the schema made them). Parsed for every module
 * in `modules`, even one whose provider is overridden. A refused value, or a
 * schema that cannot answer synchronously, refuses boot with
 * `config-validation-failed`: all sections reported together, each issue's
 * path prefixed with the section's.
 *
 * `section` is not a slot: a module declaring a section may not also require
 * or optionally read a component named `section` (`reserved-component-key`).
 */
export interface ModuleSection<S extends SectionSchema = SectionSchema> {
	/**
	 * The schema of the module's own section. Its output is the type of
	 * `deps.section`. A section that may be absent says so in the schema
	 * (`.optional()`); an absent section is otherwise refused, like any other
	 * value the schema refuses. Defaults belong in the package's
	 * `reference.conf`, not in the schema.
	 */
	readonly schema: S;
	/**
	 * The package's `config/reference.conf`, holding this section's defaults,
	 * as a `file:` URL resolved from the module's file (e.g. `new
	 * URL("../config/reference.conf", import.meta.url)` from a file directly
	 * under `src/`). Boot does not read it: `moduleReferences(modules)` collects
	 * it for the composition root to layer. The package's tests hold the file to
	 * its sections (`referenceConfProblems`, on the testing entry).
	 */
	readonly reference?: URL;
	/**
	 * Where the section sits today, as a dot-separated path of non-empty keys
	 * (`"oauth.dpop"`), for a section not yet moved under the module's name.
	 * Unset, it is the top-level key named exactly as the module (not split on
	 * dots). Keys are read as own properties only; an invalid path refuses boot
	 * (`module-section-path-invalid`). Transitional.
	 *
	 * Read from boot's composed configuration, so under a parent core's schema
	 * declares, values may arrive coerced and a `configSchema` may still inject
	 * defaults. The parsed value is written back at this path, so the `config`
	 * slot holds what the module is handed; no two modules may declare the same
	 * path.
	 */
	readonly at?: string;
	/**
	 * The paths this section moved from, so a setting still written at an old
	 * path refuses boot (`config-path-relocated`) naming its new path, rather
	 * than being ignored. Either:
	 * - a list of old paths, each moved whole as the section (`["oauth.dpop"]`);
	 * - a map from each old path to its path inside the section, `""` for the
	 *   section itself and `null` for a removed key (`{ "oauth.dpop": "",
	 *   "oauth.dpop.iat-window-seconds": "iatWindowSeconds" }`). The most
	 *   specific covering entry maps a key; keys below it carry over unchanged.
	 *   An entry written `{ to, environmentVariable: null }` moves to `to` like
	 *   a string entry, for a new path no variable binds
	 *   ({@link RelocationWithoutVariable}): the refusal names none, and no
	 *   variable may be declared renamed onto it.
	 *
	 * An old path may not be or hold a loaded module's section, overlap a new
	 * path, or overlap another loaded module's old path
	 * (`module-section-path-invalid`). A module configured only through
	 * `configSchema` declares no section path, so its old paths are not caught.
	 *
	 * A switch that decides whether a module loads (an adapter selection,
	 * `federations.<name>.enabled`) is relocated by a module that is always
	 * loaded, since the module it selects may never be. Defaults and variable
	 * bindings move with the path, and none stays at the old one; the schema
	 * rules are in `docs/release-policy.md` ("Key moved to another path").
	 *
	 * A bridge for the 0.x line: removed at the first major release; the
	 * relocated-paths drift test fails the cut that forgets.
	 */
	readonly relocatedFrom?:
		| readonly string[]
		| Readonly<Record<string, string | null | RelocationWithoutVariable>>;
	/**
	 * The environment variables whose names changed: each old name, mapped to
	 * the old path it was bound to (`{ LEGACY_RETRIES: "legacy.retries" }`).
	 * An old path {@link relocatedFrom} covers moves as it maps, and one in the
	 * module's own section that no relocation covers stays where it is; the new
	 * name is the variable its path is bound to (`environmentVariableFor`). An
	 * old path mapped to `null` was removed, and its variable has no new name.
	 *
	 * Nothing binds an old name at a path. The module's own {@link reference}
	 * binds each new name at its path, and captures every declared old and new
	 * name in the top-level `renamed-variables` section, each `null` and then
	 * `${?NAME}`, so boot judges what the resolution saw: the old name set
	 * refuses boot (`environment-variable-renamed`) unless the new one is set
	 * to the same string — a default at the new path does not count — and a
	 * removed key's variable set refuses it outright, as does a name the
	 * configuration does not capture. For a composition root's own module the
	 * reference is the root's `config/reference.conf`, layered through
	 * `moduleReferences`, never its `application.conf`. No other layer writes
	 * `renamed-variables`: a capture written by hand overrides what the
	 * resolution saw, and a root that builds its configuration by hand must
	 * capture every declared name from the environment it substitutes with,
	 * `null` when unset (`renamedVariableCaptures`, on the testing entry).
	 *
	 * A rename carries the value unchanged: a move that changes what a value
	 * means (its unit, its encoding) is not declared here. A name bound element
	 * by element (`${?NAME[]}`) cannot be declared.
	 *
	 * Each old name is a variable name, differs from its new one, and is
	 * declared by one loaded module and is no rename's new name; a new path
	 * lies in a section read at its module's name, and is not the section
	 * itself (`module-section-path-invalid`). Removed with `relocatedFrom` at
	 * the first major release.
	 */
	readonly renamedVariables?: Readonly<Record<string, string>>;
}

/**
 * What a module's section adds to its factories' deps:
 * - no section (`S` is `never`): nothing, so reading `deps.section` does not
 *   compile;
 * - a section: `readonly section`, typed as the schema's output;
 * - the widest schema ({@link SectionSchema}, the erased `Module`):
 *   `section: never`, which lets `defineModule` return `Module`. A schema typed
 *   as plain `z.ZodType` gets this too; give it its own type (`z.object(…)`)
 *   to read it.
 */
export type SectionDeps<S extends SectionSchema> = [S] extends [never]
	? unknown
	: [SectionSchema] extends [S]
		? { readonly section: never }
		: { readonly section: z.output<S> };
