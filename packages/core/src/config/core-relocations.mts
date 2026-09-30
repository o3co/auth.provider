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
 * What core's own section, `core`, moved from and the environment variables
 * renamed with it: boot holds and applies it as it does a loaded module's
 * `section.relocatedFrom` and `section.renamedVariables`, as module "core",
 * and core's `reference.conf` captures each name it declares renamed.
 */

import type { ModuleSection } from "../modules/manifest/module-section.mjs";

/** Core's declaration: the two fields of a module's `section` that say where it moved from. */
export type CoreRelocations = Pick<ModuleSection, "relocatedFrom" | "renamedVariables">;

/** Core's shipped declaration. */
export const CORE_RELOCATIONS: CoreRelocations = Object.freeze({});
