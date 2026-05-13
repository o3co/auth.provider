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
import { fileURLToPath } from "node:url";

export interface ResolvedConfigPaths {
	readonly applicationConfPath: string;
	readonly envConfPath: string;
}

/**
 * Returns the absolute path to the shipped `reference.conf` inside
 * `@o3co/auth-provider-core`. This file is the bottom layer of the
 * 3-tier HOCON precedence chain (reference.conf → application.conf → {env}.conf).
 *
 * Uses `import.meta.resolve` (Node.js Stability 1.2 RC) to resolve the
 * `./reference.conf` package export without depending on the filesystem
 * layout of `node_modules`.
 */
export function resolveLibraryReferenceConfPath(): string {
	return fileURLToPath(import.meta.resolve("@o3co/auth-provider-core/reference.conf"));
}

export function resolveConfigPaths(configDirPath: string, env: string): ResolvedConfigPaths {
	// path.resolve strips trailing slashes that fileURLToPath may preserve, so
	// the containment check below compares equal shapes (path.dirname never
	// returns a trailing separator).
	const normalizedConfigDir = path.resolve(configDirPath);
	const applicationConfPath = path.join(normalizedConfigDir, "application.conf");
	const envConfPath = path.resolve(normalizedConfigDir, `${env}.conf`);
	if (path.dirname(envConfPath) !== normalizedConfigDir) {
		throw new Error(
			`Invalid config environment name: "${env}" resolves outside ${normalizedConfigDir}`,
		);
	}
	return { applicationConfPath, envConfPath };
}
