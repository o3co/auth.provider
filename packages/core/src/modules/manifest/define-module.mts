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

import type { ComponentKey } from "./component-map.mjs";
import type { SectionSchema } from "./module-section.mjs";
import type { Module, ModuleSpec } from "./module-spec.mjs";

/**
 * Authoring entry point for module manifests. The `const` generic parameters
 * `R` and `O` capture the literal `requires` / `optional` arrays without
 * `as const`, so providers and contribution factories receive precisely typed
 * deps. `S` is inferred from `section.schema`, so the deps also carry the
 * module's own section, typed as the schema's output.
 *
 * A call that writes its type arguments (`defineModule<Requires, Optional>(…)`)
 * infers none: a sectioned module then names its schema's type third
 * (`typeof MySection`), and one declaring `authoritative` keys names them
 * fourth. Otherwise `P` is inferred from the keys of `provides`, so
 * `authoritative` compiles only with keys the module provides.
 *
 * @example
 * ```typescript
 * export const myModule = defineModule({
 *   name: "my-module",
 *   requires: ["logger"],         // inferred as readonly ["logger"]
 *   section: { schema: z.object({ retries: z.number() }) },
 *   provides: {
 *     auditSink: ({ logger, section }) => createAuditSink(logger, section.retries),
 *   },
 * });
 * ```
 */
export function defineModule<
	const R extends ComponentKey = never,
	const O extends ComponentKey = never,
	S extends SectionSchema = never,
	P extends ComponentKey = never,
>(spec: ModuleSpec<R, O, S, P>): Module {
	// Pure pass-through: the type parameters serve inference only. Not frozen:
	// the type-level `readonly` is the contract; boot freezes only the
	// projected views it builds (synthetic resolvers).
	return spec;
}
