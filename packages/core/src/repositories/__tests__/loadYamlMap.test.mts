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
import { inspect } from "node:util";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { z } from "zod";
import { loadYamlMap } from "#/repositories/loadYamlMap.mjs";

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

	describe("a file that is not YAML", () => {
		// js-yaml's exception quotes the lines around the error in its message
		// and holds the whole file in `mark.buffer`; a clients or users file
		// holds secrets. What is thrown names the file, the line and column
		// and the parser's reason, and carries nothing of the file.
		const thrownBy = (content: string): Error => {
			const fp = writeYaml(content);
			try {
				loadYamlMap(fp, TestSchema);
			} catch (err) {
				return err as Error;
			}
			throw new Error("loadYamlMap did not throw");
		};
		const carriesNothingOf = (err: Error, ...markers: readonly string[]): void => {
			const printed = inspect(err, { depth: Number.POSITIVE_INFINITY, showHidden: true });
			for (const marker of markers) {
				expect(err.message).not.toContain(marker);
				expect(printed).not.toContain(marker);
			}
			expect(err.cause).toBeUndefined();
			expect(Object.hasOwn(err, "mark")).toBe(false);
		};

		it("names the file, the line and column and the reason, and quotes none of the file", () => {
			const err = thrownBy(
				[
					"web:",
					"  name: before-secret-marker",
					"  redirectUris:",
					"   - https://rp.test/cb",
					"  bad",
					"other:",
					"  name: after-secret-marker",
					"",
				].join("\n"),
			);
			expect(err.message).toBe(
				`Invalid YAML in ${path.join(tmpDir, "test.yaml")} at 5:6: expected ':' after a mapping key`,
			);
			carriesNothingOf(err, "before-secret-marker", "after-secret-marker", "rp.test");
		});

		it("leaves out what the parser quotes of the file into its reason", () => {
			// An unquoted value that starts with `*` or `!` is read as an alias or
			// a tag, and the parser names it in the reason itself.
			for (const [content, marker, reason] of [
				["web:\n  name: *alias-secret-marker\n", "alias-secret-marker", "unidentified alias"],
				["web:\n  name: !tag-secret-marker x\n", "tag-secret-marker", "unknown scalar tag"],
				["web:\n  name: !h!handle-secret-marker x\n", "h!", "undeclared tag handle"],
				[
					"web:\n  name: !seq-secret-marker\n    - a\n",
					"seq-secret-marker",
					"unknown sequence tag",
				],
				[
					"web:\n  name: !map-secret-marker\n    a: b\n",
					"map-secret-marker",
					"unknown mapping tag",
				],
				[
					"web:\n  name: !<tag{chars-secret-marker}> x\n",
					"chars-secret-marker",
					"tag name cannot contain such characters",
				],
				[
					"%TAG !suffixsecret! tag:a:\n%TAG !suffixsecret! tag:b:\n---\nweb: 1\n",
					"suffixsecret",
					"there is a previously declared suffix for",
				],
			] as const) {
				const err = thrownBy(content);
				expect(err.message).toMatch(new RegExp(`at \\d+:\\d+: ${reason}$`));
				carriesNothingOf(err, marker);
			}
		});
	});
});
