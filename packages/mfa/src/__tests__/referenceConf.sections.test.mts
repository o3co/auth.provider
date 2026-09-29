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
 * core's `packageReferenceProblems`, the check every package with defaults
 * runs over its own file.
 */

import { packageReferenceProblems } from "@o3co/auth-provider-core/testing";
import { parseFile } from "@o3co/ts.hocon";
import { describe, expect, it } from "vitest";
import { mfaModule } from "#/module.mjs";
import { mfaTotpFactorModule } from "#/totp/module.mjs";

/** The package's defaults, as a composition root finds them. */
const REFERENCE = new URL("../../config/reference.conf", import.meta.url);

describe("the package's config/reference.conf (#728)", () => {
	const modules = [mfaModule(), mfaTotpFactorModule];

	it("is read at the sections its modules declare", () => {
		expect(modules.map((module) => module.section?.at)).toEqual(["mfa", "mfa.factors.totp"]);
	});

	it("is declared by each of them and holds only their sections, which their schemas parse without losing a path", () => {
		const read = (path: string): unknown => parseFile(path, { env: {} }).toObject();
		expect(packageReferenceProblems({ reference: REFERENCE, modules, read })).toEqual([]);
	});
});
