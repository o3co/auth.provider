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
 * Stage 5 of the A2-β boot planner pipeline.
 *
 * Steps:
 * 1. `Object.freeze(registry.material.components)` — the component map is
 *    now structurally immutable. Consumer code that captures a reference
 *    cannot mutate the map.
 * 2. For each `(kind, collector)` in `registry.registries`: if the collector
 *    exposes a `freeze()` method, call it. Skip otherwise. This covers
 *    name-keyed registries (`GrantRegistry`, `ExchangeTokenValidatorRegistry`,
 *    consumer-defined registries), `RouteCollector` (always has `freeze()`),
 *    and opt-in `ListCollector<V>` instances.
 *
 * `AdapterFactory` is explicitly out of scope per A6+A7 §2.3 — it is
 * composition-root-shaped with no module-init activation boundary and is not
 * stored in `registry.registries`. The boot planner does NOT iterate or freeze
 * any AdapterFactory instance.
 *
 * Per A2-β §5.5.
 */
export function freezeWorld(registry) {
    // Step 1: structurally immobilise the component map.
    Object.freeze(registry.material.components);
    // Step 2: call freeze() on every collector that exposes it.
    for (const [, collector] of registry.registries) {
        if (typeof collector.freeze === "function") {
            collector.freeze();
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
