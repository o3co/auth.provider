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
import path from "node:path";
export function resolveConfigPaths(configDirPath, env) {
    // path.resolve strips trailing slashes that fileURLToPath may preserve, so
    // the containment check below compares equal shapes (path.dirname never
    // returns a trailing separator).
    const normalizedConfigDir = path.resolve(configDirPath);
    const applicationConfPath = path.join(normalizedConfigDir, "application.conf");
    const envConfPath = path.resolve(normalizedConfigDir, `${env}.conf`);
    if (path.dirname(envConfPath) !== normalizedConfigDir) {
        throw new Error(`Invalid config environment name: "${env}" resolves outside ${normalizedConfigDir}`);
    }
    return { applicationConfPath, envConfPath };
}
