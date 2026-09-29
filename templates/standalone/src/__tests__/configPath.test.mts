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

import { existsSync } from "node:fs";
import { isAbsolute } from "node:path";
import { fileURLToPath } from "node:url";
import { coreReference } from "@o3co/auth-provider-core";
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

describe("core's reference.conf, as the template layers it", () => {
	// `coreReference()` names the file `@o3co/auth-provider-core` exports as
	// `./reference.conf`: the one a composition root that installed the
	// package would resolve, and the bottom of every layering the template
	// makes (`readSwitches`, `resolveForBoot`).
	it("is the file the package exports as ./reference.conf, and it exists", () => {
		const path = fileURLToPath(coreReference());
		expect(isAbsolute(path)).toBe(true);
		expect(existsSync(path)).toBe(true);
		expect(path).toBe(
			fileURLToPath(import.meta.resolve("@o3co/auth-provider-core/reference.conf")),
		);
	});
});
