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
import fs from "node:fs";
import yaml from "js-yaml";
export const loadYamlMap = (filePath, schema) => {
    const content = fs.readFileSync(filePath, "utf-8");
    const raw = yaml.load(content);
    if (raw !== null && raw !== undefined && (typeof raw !== "object" || Array.isArray(raw))) {
        throw new Error(`Invalid configuration in ${filePath}: expected a YAML mapping`);
    }
    const data = (raw ?? {});
    const map = new Map();
    for (const [key, entry] of Object.entries(data)) {
        const result = schema.safeParse(entry);
        if (!result.success) {
            throw new Error(`Invalid entry "${key}" in ${filePath}: ${result.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join(", ")}`);
        }
        map.set(key, result.data);
    }
    return map;
};
