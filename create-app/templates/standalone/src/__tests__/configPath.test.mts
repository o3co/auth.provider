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

import { describe, expect, it } from "vitest";
import { resolveConfigPaths } from "../configPath.mjs";

describe("resolveConfigPaths", () => {
	it("accepts a configDirPath with a trailing slash (regression: fileURLToPath preserves trailing /)", () => {
		const { applicationConfPath, envConfPath } = resolveConfigPaths(
			"/home/node/templates/standalone/config/",
			"production",
		);
		expect(applicationConfPath).toBe("/home/node/templates/standalone/config/application.conf");
		expect(envConfPath).toBe("/home/node/templates/standalone/config/production.conf");
	});

	it("accepts a configDirPath without a trailing slash", () => {
		const { applicationConfPath, envConfPath } = resolveConfigPaths(
			"/home/node/templates/standalone/config",
			"development",
		);
		expect(applicationConfPath).toBe("/home/node/templates/standalone/config/application.conf");
		expect(envConfPath).toBe("/home/node/templates/standalone/config/development.conf");
	});

	it("rejects env names that resolve outside configDirPath (path traversal)", () => {
		expect(() =>
			resolveConfigPaths("/home/node/templates/standalone/config/", "../secrets"),
		).toThrow(/resolves outside/);
	});

	it("rejects env names containing a path separator", () => {
		expect(() =>
			resolveConfigPaths("/home/node/templates/standalone/config/", "nested/env"),
		).toThrow(/resolves outside/);
	});
});
