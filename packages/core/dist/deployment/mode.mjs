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
 * `single` or `multi` as `core.deployment.mode` states it, `unset` for anything
 * else — absence included. Core's schema admits only the two, or none; any
 * other value reaches here only through a configuration the schema never
 * saw, and reads as `unset`, never as `single` or `multi`.
 */
export function deploymentModeOf(config) {
    const mode = config?.core
        ?.deployment?.mode;
    return mode === "single" || mode === "multi" ? mode : "unset";
}
/**
 * `value` when it is one of the slot's three values, or a `TypeError` naming
 * `name`, the value's source — absence included. A reader refuses what it
 * cannot read as a mode rather than reading it as `unset`: a mode lost on the
 * way would lift the refusals `multi` makes.
 */
export function checkDeploymentMode(value, name) {
    if (value === "single" || value === "multi" || value === "unset")
        return value;
    throw new TypeError(`${name} must be "single", "multi" or "unset"`);
}
