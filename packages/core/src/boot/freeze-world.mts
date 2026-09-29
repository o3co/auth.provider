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
 * boot/freeze-world.mts: stage 5 of the boot planner, which turns the
 * `RegistryWorld` into a `FrozenWorld`.
 */

import type { FrozenWorld, RegistryWorld } from "./types.mjs";

/**
 * Stage 5 of the boot planner. Freezes the component map, so code holding a
 * reference cannot mutate it, then calls `freeze()` on every collector in
 * `registry.registries` that has one (the built-in name-keyed collectors,
 * consumer-defined collectors, `RouteCollector`, and the `ListCollector`s
 * that define it).
 *
 * `AdapterFactory` is not frozen: it is composition-root-shaped, has no
 * module-init activation boundary, and is not stored in `registry.registries`.
 */
export function freezeWorld(registry: RegistryWorld): FrozenWorld {
	Object.freeze(registry.material.components);

	for (const [, collector] of registry.registries) {
		if (typeof (collector as { freeze?: unknown }).freeze === "function") {
			(collector as { freeze(): void }).freeze();
		}
	}

	return {
		components: registry.material.components,
		registries: registry.registries,
		routes: registry.routes,
		cleanups: registry.material.cleanups,
		externalKeys: registry.material.externalKeys,
	};
}
