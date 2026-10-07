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
 * The path of the first object or array in `value` that is not frozen —
 * `value` itself included — or `undefined` when every one is. A settings
 * slot is read by several modules, and one of them changing it would change
 * what the others read.
 */
export function unfrozenPath(value, path = "the value") {
    if (typeof value !== "object" || value === null)
        return undefined;
    if (!Object.isFrozen(value))
        return path;
    for (const [key, member] of Object.entries(value)) {
        const found = unfrozenPath(member, `${path}.${key}`);
        if (found !== undefined)
            return found;
    }
    return undefined;
}
