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
import type { Module, ModuleContext, PathResolver } from "../types.mjs";

describe("Module interface", () => {
	it("PathResolver is a function from string to string", () => {
		const resolver: PathResolver = (specifier: string) => `/resolved/${specifier}`;
		expect(resolver("passport")).toBe("/resolved/passport");
	});

	it("Module has name and async init", async () => {
		let initCalled = false;
		const module: Module = {
			name: "test-module",
			async init(_context: ModuleContext): Promise<void> {
				initCalled = true;
			},
		};

		expect(module.name).toBe("test-module");
		expect(initCalled).toBe(false);
		// init requires a ModuleContext — tested in app.test.mts
	});
});
