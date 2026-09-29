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
import type { SectionDeps, SectionSchema } from "./module-section.mjs";

/**
 * Typed dependency object derived from a module's `requires` and `optional`
 * key sets, and from its section's schema.
 *
 * - Keys in `R` are non-optional, typed `NonNullable<ComponentMap[K]>`: every
 *   slot is declared `slot?: T`, and boot's missing-required-component check
 *   guarantees a required slot is present.
 * - Keys in `O` are optional, typed `ComponentMap[K] | undefined`.
 * - `S`, the module's section schema, adds `readonly section` typed as its
 *   output, or nothing when `never` (`SectionDeps`). `section` is not a slot:
 *   boot parses it at stage 1 and sets it beside the slots.
 */
export type ProviderDeps<
	R extends ComponentKey = never,
	O extends ComponentKey = never,
	S extends SectionSchema = never,
> = {
	readonly [K in R]: NonNullable<ComponentMap[K]>;
} & {
	readonly [K in O]?: ComponentMap[K];
} & SectionDeps<S>;

/**
 * A provider materialises one ComponentMap slot from the module's typed deps,
 * synchronously or not. Boot invokes it at most once per `createApp` call.
 */
export type Provider<K extends ComponentKey, Deps> = (
	deps: Deps,
) => ComponentMap[K] | Promise<ComponentMap[K]>;
