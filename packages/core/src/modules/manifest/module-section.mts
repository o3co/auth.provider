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
 * A module's own configuration section (#728): the manifest declares the
 * schema of the one section it owns, and every factory of the module
 * receives that section parsed, as `deps.section`, instead of reading the
 * whole configuration.
 *
 * #728 decides the target: a top-level section is owned by exactly one
 * module and named after it verbatim, in kebab-case (`device-grant {}`,
 * `redis-consent-store {}`); its keys are camelCase; its defaults live only
 * in the owning package's `config/reference.conf`; and a module receives only
 * its own section, never another module's. This file is the vocabulary for
 * that. It moves nothing: `at` names where a section sits until it is moved
 * under the module's name, `reference` and `relocatedFrom` are declarations
 * boot does not act on yet, and a module that declares no section is booted
 * as before.
 */

import type { z } from "zod";

/**
 * The schema a module's section is parsed with: any Zod schema. It is the
 * widest one, so `Module` — the erased manifest boot takes — is written with
 * it, and any sectioned manifest is assignable to `Module`.
 */
export type SectionSchema = z.ZodType;

/**
 * The `section` field of a manifest: the module's own configuration section.
 *
 * Boot reads the value at {@link at} out of the configuration it already has
 * (the parsed configuration the `config` slot holds), parses it with
 * {@link schema} at stage 1 — synchronously, once — and hands the parsed
 * value to every factory of the module as `deps.section`. A value the schema
 * refuses refuses boot with `config-validation-failed`, each issue's path
 * prefixed with the section's, so the error names what the operator wrote
 * (`device-grant.codeLifetimeSeconds`); every refused section is reported in
 * the one error, and so is a schema that cannot answer synchronously (an
 * async refinement, a transform that throws). No factory of any module runs
 * before that.
 *
 * A section is parsed for every module in `modules`, whether or not any of
 * its factories runs — a module whose provider an `overrideComponents` entry
 * replaces included.
 *
 * `deps.section` is one object, deeply frozen, handed to every factory of the
 * module: plain data — objects and arrays — is a frozen copy, apart from the
 * `config` slot even where the schema passed a subtree through
 * (`z.unknown()`); a value that is not plain data (a `URL`, a `Buffer`, a
 * class instance a transform built) is handed over as the schema made it.
 *
 * `section` is not a slot, and a module that declares a section may not also
 * require or optionally read a component named `section` — its deps would
 * carry both under one name — which refuses boot (`reserved-component-key`).
 * A component named `section` is otherwise an ordinary slot: provided, read
 * by a module that declares no section, bootstrapped or overridden.
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
	 * The package's `config/reference.conf`, which holds this section's
	 * defaults: a `file:` URL that names that file wherever the module's own
	 * file sits. Resolved from the module's file, the relative part depends on
	 * how deep that file is: `new URL("../config/reference.conf",
	 * import.meta.url)` from a file directly under `src/` (and so `dist/`),
	 * `"../../config/reference.conf"` from one a directory further down.
	 *
	 * Declared, not yet read: boot does not layer the references beneath the
	 * configuration yet, so the composition root still layers them itself.
	 * The loader that will is what resolves and reads this URL.
	 */
	readonly reference?: URL;
	/**
	 * Where the section sits today, as a dot-separated path of keys
	 * (`"oauth.dpop"`, `"redisConsentStore"`), for a section that has not
	 * moved under the module's name yet. Unset, the section is the top-level
	 * key named exactly as the module is (`name`, not split on dots). Every
	 * key must be non-empty — `""`, `"a..b"`, `".a"` and `"a."` refuse boot
	 * (`module-section-path-invalid`) — and each is read as an own property,
	 * never one an object inherits. A transitional field: it goes once every
	 * section sits under its module's name.
	 *
	 * The section is read from the configuration *after* core's schema parsed
	 * it, the object the `config` slot holds, so a module moved onto
	 * `deps.section` sees what it read from `config` before. That has a
	 * consequence for a path under a parent core's schema declares (`oauth`,
	 * `http`, `redisConsentStore`, …): core's schema strips the keys it does not
	 * declare there and coerces the ones it does, and a module's `configSchema`
	 * still composed with it can inject defaults. So a key survives to the
	 * section only if core's schema — or a `configSchema` still present —
	 * keeps it. Keep the module's `configSchema`, or core's mirror of the
	 * section, until the loader parses each section on its own.
	 */
	readonly at?: string;
	/**
	 * The dot-separated paths this section moves from, so that a setting
	 * still written under an old path can refuse boot naming the new one,
	 * rather than be ignored.
	 *
	 * Declared, not yet enforced: boot neither reads nor refuses these paths
	 * yet.
	 */
	readonly relocatedFrom?: readonly string[];
}

/**
 * What a module's section adds to the deps its factories receive:
 *
 * - no section declared (`S` is `never`): nothing — `deps.section` does not
 *   exist, so reading it is a compile error rather than an `undefined`;
 * - a section declared: `readonly section`, typed as the schema's output;
 * - the widest schema, {@link SectionSchema} itself — the erased `Module`
 *   boot takes: `section: never`. Every sectioned manifest's factories accept
 *   that, which is what lets `defineModule` return `Module`; boot builds the
 *   deps object and hands it over untyped, so nothing reads the erased type.
 *   A manifest whose schema is typed as plain `z.ZodType` gets the same
 *   `never` — give the schema its own type (`z.object(…)`) to read it.
 */
export type SectionDeps<S extends SectionSchema> = [S] extends [never]
	? unknown
	: [SectionSchema] extends [S]
		? { readonly section: never }
		: { readonly section: z.output<S> };
