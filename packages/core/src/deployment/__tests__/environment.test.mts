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
 * The name a deployment selected its configuration by, as every guard that
 * refuses a development-only thing reads it: trimmed and in lower case,
 * production or staging whichever of the names consulted says so, and
 * development or test only when every name set says so and one is set.
 */

import { describe, expect, it } from "vitest";
import {
	isDevelopmentEnvironment,
	productionEnvironmentIn,
	readEnvironmentName,
} from "#/index.mjs";

describe("readEnvironmentName", () => {
	it("reads a name trimmed and in lower case, and anything else, or nothing, as none", () => {
		expect(readEnvironmentName(" Production\n")).toBe("production");
		expect(readEnvironmentName("development")).toBe("development");
		for (const value of [undefined, null, "", "   ", 7, {}]) {
			expect(readEnvironmentName(value), JSON.stringify(value)).toBeUndefined();
		}
	});
});

describe("productionEnvironmentIn", () => {
	it("answers the first name that reads as production or staging, whatever its case and the whitespace around it", () => {
		expect(productionEnvironmentIn(["development", " STAGING "])).toBe("staging");
		expect(productionEnvironmentIn([undefined, "Production", "staging"])).toBe("production");
		expect(productionEnvironmentIn(["production\n"])).toBe("production");
	});

	it("answers none when no name does, another name that contains one included", () => {
		for (const names of [
			[],
			[undefined, ""],
			["development", "test"],
			["preproduction", "production-like", "stage"],
		]) {
			expect(productionEnvironmentIn(names), JSON.stringify(names)).toBeUndefined();
		}
	});
});

describe("isDevelopmentEnvironment", () => {
	it("answers yes when every name set reads as development or test, whatever its case and the whitespace around it", () => {
		for (const names of [
			["development"],
			[" Test\n"],
			["development", "test"],
			[undefined, "DEVELOPMENT", ""],
		]) {
			expect(isDevelopmentEnvironment(names), JSON.stringify(names)).toBe(true);
		}
	});

	it("answers no when no name is set", () => {
		for (const names of [[], [undefined], ["", "   "], [null, 7]]) {
			expect(isDevelopmentEnvironment(names), JSON.stringify(names)).toBe(false);
		}
	});

	it("answers no when any name set reads as something else, production and an alias of it included", () => {
		for (const names of [
			["prod"],
			["development", "production"],
			["test", "staging"],
			["development", "qa"],
			["dev"],
			["testing"],
			[undefined, "local"],
		]) {
			expect(isDevelopmentEnvironment(names), JSON.stringify(names)).toBe(false);
		}
	});
});
