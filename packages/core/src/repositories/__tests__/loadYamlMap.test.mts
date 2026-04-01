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
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { z } from "zod";
import { loadYamlMap } from "../loadYamlMap.mjs";

const TestSchema = z
	.object({
		name: z.string(),
		value: z.number().optional(),
	})
	.strict();

describe("loadYamlMap", () => {
	let tmpDir: string;

	beforeEach(() => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "load-yaml-map-"));
	});

	afterEach(() => {
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	const writeYaml = (content: string): string => {
		const fp = path.join(tmpDir, "test.yaml");
		fs.writeFileSync(fp, content);
		return fp;
	};

	it("loads a YAML mapping into a Map with validated entries", () => {
		const fp = writeYaml(`
foo:
  name: Foo
  value: 42
bar:
  name: Bar
`);
		const map = loadYamlMap(fp, TestSchema);

		expect(map.size).toBe(2);
		expect(map.get("foo")).toEqual({ name: "Foo", value: 42 });
		expect(map.get("bar")).toEqual({ name: "Bar" });
	});

	it("returns empty Map for empty YAML file", () => {
		const fp = writeYaml("");
		const map = loadYamlMap(fp, TestSchema);

		expect(map.size).toBe(0);
	});

	it("throws on non-mapping YAML (array)", () => {
		const fp = writeYaml("- item1\n- item2");
		expect(() => loadYamlMap(fp, TestSchema)).toThrow("expected a YAML mapping");
	});

	it("throws on invalid entry that fails schema validation", () => {
		const fp = writeYaml(`
foo:
  name: 123
`);
		expect(() => loadYamlMap(fp, TestSchema)).toThrow("foo");
	});
});
