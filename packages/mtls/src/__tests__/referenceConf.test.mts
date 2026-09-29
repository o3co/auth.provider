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
 * The package's `config/reference.conf` (#728): the modules that read it
 * declare it as their section's reference, and it holds only their
 * sections, which their section schemas parse without losing a path —
 * core's `referenceConfProblems`, the check every package with defaults
 * runs over its own file.
 */

import { fileURLToPath } from "node:url";
import { referenceConfProblems } from "@o3co/auth-provider-core/testing";
import { parseFile } from "@o3co/ts.hocon";
import { describe, expect, it } from "vitest";
import { mtlsModule } from "#/module.mjs";

/** The package's defaults, as a composition root finds them. */
const REFERENCE = new URL("../../config/reference.conf", import.meta.url);

describe("the package's config/reference.conf (#728)", () => {
	const modules = [mtlsModule];

	it("is the reference each of its modules declares, at the section it reads", () => {
		for (const module of modules) {
			expect(module.section?.reference?.href, module.name).toBe(REFERENCE.href);
		}
		expect(modules.map((module) => module.section?.at)).toEqual(["oauth.mtls"]);
	});

	it("holds only those modules' sections, which their schemas parse without losing a path", () => {
		const tree = parseFile(fileURLToPath(REFERENCE), { env: {} }).toObject();
		expect(referenceConfProblems({ tree, reference: REFERENCE, modules })).toEqual([]);
	});
});
