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

import type { ComponentKey, ComponentMap } from "./component-map.mjs";

/**
 * Typed dependency object derived from a module's `requires` and `optional`
 * key sets.
 *
 * - Keys in `R` (required) appear as `readonly` non-optional fields with
 *   the slot's value type from ComponentMap.
 * - Keys in `O` (optional) appear as `readonly` optional fields with type
 *   `ComponentMap[K] | undefined`.
 *
 * Per A2-α §3.1.
 */
export type ProviderDeps<R extends ComponentKey = never, O extends ComponentKey = never> = {
	readonly [K in R]: ComponentMap[K];
} & {
	readonly [K in O]?: ComponentMap[K];
};

/**
 * A provider materialises a single ComponentMap slot from the module's
 * typed deps object. Per A2-α §3.1 / §3.2: a single async-or-sync factory
 * shape; no discriminated provider union; invoked at most once per
 * createApp call (boot planner enforces).
 *
 * The return type is `ComponentMap[K] | Promise<ComponentMap[K]>` — a
 * provider may return synchronously when no async work is needed.
 */
export type Provider<K extends ComponentKey, Deps> = (
	deps: Deps,
) => ComponentMap[K] | Promise<ComponentMap[K]>;
