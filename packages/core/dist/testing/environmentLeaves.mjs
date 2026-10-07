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
 * The guard that every configuration leaf a module reads takes the string an
 * environment variable arrives as. HOCON substitutes `${?VAR}` as a string,
 * always, and boot's composed parse is plain Zod, which does not coerce a
 * bare `z.boolean()` or `z.number()`. Core's base (`CoreConfigSchema`)
 * declares core's own section alone, which no module's section is, so a
 * module's own leaf must read the string.
 */
import { unreadableLeaves } from "../config/schema-path.mjs";
/**
 * Every leaf the modules' section schemas declare, each at its module's name,
 * that would refuse an environment variable's string — a bare `z.boolean()`, or a
 * `z.number()` that does not coerce — as `<module>: <path>`, sorted. A record's value is `*`, a list's
 * element `[]`.
 */
export function unreadableModuleLeaves(modules) {
    return modules
        .flatMap((module) => {
        // Paths inside the section; the module's name is one key in front, never split on its dots.
        const section = module.section ? unreadableLeaves(module.section.schema) : [];
        return section.map(({ path }) => `${module.name}: ${path === "" ? module.name : `${module.name}.${path}`}`);
    })
        .filter((entry, index, all) => all.indexOf(entry) === index)
        .sort();
}
