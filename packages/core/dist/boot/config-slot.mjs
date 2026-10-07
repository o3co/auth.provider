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
import { defaultRefreshTokenFamilyRevocationModule, defaultRefreshTokenFamilyRotationModule, } from "../refresh-token-family/module.mjs";
import { sessionLifecycleModule } from "../session-lifecycle/module.mjs";
import { BootError } from "./types.mjs";
/** The slot that holds the whole configuration. */
const CONFIG_SLOT = "config";
/**
 * Core's modules that read the whole configuration: the manifest objects core
 * ships, held by identity, never by name, so a module of another package
 * named as one of them, or a copy of one, is not one. A module of core's that
 * comes to read `config` is added here; the list shrinks as they move to
 * their own sections and slots.
 */
export const CONFIG_READING_CORE_MODULES = Object.freeze([
    sessionLifecycleModule,
    defaultRefreshTokenFamilyRotationModule,
    defaultRefreshTokenFamilyRevocationModule,
]);
const configReaders = new Set(CONFIG_READING_CORE_MODULES);
/**
 * A module that is not one of {@link CONFIG_READING_CORE_MODULES} and lists
 * `config` in its `requires` or its `optional` refuses boot
 * (`reserved-component-key`), naming the module and the slot: a module reads
 * its own section, as `deps.section`, and what another module owns through a
 * slot. `rawModules` are the manifests as the composition listed them, which
 * carry their identity; `modules` their normalised lists, index for index.
 * @internal
 */
export function checkConfigSlotCoreOnly(rawModules, modules) {
    modules.forEach((m, index) => {
        const raw = rawModules[index];
        if (raw !== undefined && configReaders.has(raw))
            return;
        const sources = [
            ["module-requires", m.requires, "requires"],
            ["module-optional", m.optional, "optionally reads"],
        ];
        for (const [source, keys, verb] of sources) {
            if (!keys.includes(CONFIG_SLOT))
                continue;
            throw new BootError({
                message: `Module "${m.name}" ${verb} "${CONFIG_SLOT}", the whole configuration, which only ` +
                    "core's own modules read. Read the module's own section instead: declare " +
                    "`section: { schema }` on the module and read `deps.section`; read what another " +
                    "module owns through a slot.",
                reason: "reserved-component-key",
                stage: "validateManifests",
                details: {
                    reason: "reserved-component-key",
                    componentKey: CONFIG_SLOT,
                    source,
                    module: m.name,
                },
            });
        }
    });
}
