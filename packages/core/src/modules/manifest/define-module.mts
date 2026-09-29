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
 * Authoring entry point for v0.5.0 manifests. The `const` generic
 * parameters R and O capture the literal `requires` / `optional` arrays
 * at the call site without the author writing `as const`, so providers
 * and contribution factories receive a precisely-typed deps object.
 * `S` is inferred from `section.schema`, so the same deps object carries
 * the module's own section, typed as the schema's output (#728).
 *
 * A call that writes its type arguments (`defineModule<Requires,
 * Optional>(…)`) infers none of them: a sectioned module that does names
 * its schema's type as the third (`typeof MySection`), and one that
 * declares `authoritative` keys names them as the fourth. `P` is otherwise
 * inferred from the keys of `provides`, so `authoritative` compiles only
 * with keys the module provides (#728).
 *
 * Per A2-α §3.1 (TypeScript 5.0+ `const` modifier on generic parameters).
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
	// Pure pass-through. The boot planner (Phase 4) consumes the erased
	// Module type; the type-level R/O information is captured at the
	// defineModule call site for inference but not used at runtime.
	//
	// Object.freeze omitted because the manifest is itself `readonly` at
	// the type level; runtime freezing is a defensive belt the boot planner
	// applies to projected views (synthetic resolvers per A2-α §6.5), not
	// to user-authored manifests. Per principle spec Theme D guidance: the
	// type-level readonly is the contract.
	return spec;
}
