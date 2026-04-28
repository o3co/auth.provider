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
import type { Module, ModuleSpec } from "./module-spec.mjs";

/**
 * Authoring entry point for v0.5.0 manifests. The `const` generic
 * parameters R and O capture the literal `requires` / `optional` arrays
 * at the call site without the author writing `as const`, so providers
 * and contribution factories receive a precisely-typed deps object.
 *
 * Per A2-α §3.1 (TypeScript 5.0+ `const` modifier on generic parameters).
 *
 * @example
 * ```typescript
 * export const myModule = defineModule({
 *   name: "my-module",
 *   requires: ["config"],         // inferred as readonly ["config"]
 *   provides: {
 *     auditSink: ({ config }) => createAuditSink(config),
 *   },
 * });
 * ```
 */
export function defineModule<
	const R extends ComponentKey = never,
	const O extends ComponentKey = never,
>(spec: ModuleSpec<R, O>): Module {
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
