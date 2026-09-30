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
 * Every variable a module of the full set — or core, for its own section —
 * declares renamed is bound as boot's judgement needs, across every layer the
 * repository ships (each package's `config/reference.conf` and the standalone
 * template's `config/*.conf`): its old and new names captured in
 * `renamed-variables`, its new name bound at its path, its old name bound
 * nowhere else. A declaration of a name a shipped layer still binds would
 * refuse every operator who sets it; a new name bound nowhere would drop
 * what an operator sets under it.
 */

import { readdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { CORE_RELOCATIONS, renamedVariableProblems } from "@o3co/auth-provider-core/testing";
import { parseFile } from "@o3co/ts.hocon";
import { afterAll, describe, expect, it } from "vitest";
import { composeFullSet, type FullSet } from "./full-set.fixture.mts";

const ROOT = fileURLToPath(new URL("../../../../", import.meta.url));

/** Every configuration layer the repository ships. */
const LAYERS: readonly string[] = [
	...readdirSync(join(ROOT, "packages"), { withFileTypes: true })
		.filter((entry) => entry.isDirectory())
		.map((entry) => join(ROOT, "packages", entry.name, "config", "reference.conf"))
		.filter((path) => {
			try {
				return readdirSync(join(path, "..")).includes("reference.conf");
			} catch {
				return false;
			}
		}),
	...readdirSync(join(ROOT, "templates", "standalone", "config"))
		.filter((file) => file.endsWith(".conf"))
		.map((file) => join(ROOT, "templates", "standalone", "config", file)),
];

const read = (path: string, env: Readonly<Record<string, string>>): unknown =>
	parseFile(path, { env: { ...env } }).toObject();

let fullSet: FullSet | undefined;

afterAll(async () => {
	await fullSet?.handle.dispose();
});

describe("the variables renamed with a move, across every shipped layer", () => {
	it("reads every package's reference and the template's layers, and holds renames the full set declares", async () => {
		fullSet = await composeFullSet();
		expect(LAYERS.some((path) => path.endsWith(join("core", "config", "reference.conf")))).toBe(
			true,
		);
		expect(LAYERS.some((path) => path.endsWith(join("mfa", "config", "reference.conf")))).toBe(
			true,
		);
		expect(LAYERS.some((path) => path.endsWith("application.conf"))).toBe(true);
		expect(fullSet.modules.some((module) => module.section?.renamedVariables !== undefined)).toBe(
			true,
		);

		expect(
			renamedVariableProblems({
				modules: fullSet.modules,
				core: CORE_RELOCATIONS,
				layers: LAYERS,
				read,
			}),
		).toEqual([]);
	});
});
