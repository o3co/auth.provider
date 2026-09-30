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
 * `relocationBindingProblems`, on core's testing entry: the relocation
 * refusal names, for a key moved to a new path, the variable the naming rule
 * gives that path, so a layer the composition ships binds it there; and a
 * new path declared bound to no variable (`{ to, environmentVariable: null }`)
 * is bound by no layer. The most specific relocation of a module decides a
 * path, as it does at boot.
 */

import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { parseFile } from "@o3co/ts.hocon";
import { describe, expect, it } from "vitest";
import { z } from "zod";
import { CORE_RELOCATIONS } from "#/config/core-relocations.mjs";
import { coreReference } from "#/config/references.mjs";
import { jwksModule } from "#/jwks/module.mjs";
import { defineModule } from "#/modules/manifest/index.mjs";
import { relocationBindingProblems } from "#/testing/index.mjs";

const read = (path: string, env: Readonly<Record<string, string>>): unknown =>
	parseFile(path, { env: { ...env } }).toObject();

/** The variables a layer substitutes, outside its comments. */
const variables = (path: string): readonly string[] => [
	...new Set(
		[
			...readFileSync(path, "utf8")
				.split("\n")
				.filter((line) => !/^\s*(#|\/\/)/.test(line))
				.join("\n")
				.matchAll(/\$\{\??([A-Za-z0-9_]+)\}/g),
		].map((match) => String(match[1])),
	),
];

/** `text` in a file of its own. */
function layer(text: string): string {
	const file = join(mkdtempSync(join(tmpdir(), "relocation-bindings-")), "reference.conf");
	writeFileSync(file, text);
	return file;
}

const relocating = (relocatedFrom: Record<string, unknown>) =>
	defineModule({
		name: "fixture-relocating",
		section: {
			schema: z.object({}).passthrough(),
			relocatedFrom: relocatedFrom as never,
		},
	});

const problems = (
	modules: Parameters<typeof relocationBindingProblems>[0]["modules"],
	text: string,
) => relocationBindingProblems({ modules, layers: [layer(text)], read, variables });

describe("relocationBindingProblems", () => {
	it("finds nothing wrong when each moved key's variable is bound at its new path", () => {
		expect(
			problems(
				[relocating({ "legacy.retries": "retries", legacy: "" })],
				`fixture-relocating {\n  retries = 3\n  retries = \${?FIXTURE_RELOCATING_RETRIES}\n  label = \${?FIXTURE_RELOCATING_LABEL}\n}\n`,
			),
		).toEqual([]);
	});

	it("names a moved key whose new path no layer binds: the refusal would name a variable nothing reads", () => {
		expect(
			problems(
				[relocating({ "legacy.retries": "retries", "legacy.label": "label" })],
				`fixture-relocating {\n  retries = \${?FIXTURE_RELOCATING_RETRIES}\n  label = old\n}\n`,
			),
		).toEqual([
			'module "fixture-relocating": legacy.label moves to fixture-relocating.label, whose variable FIXTURE_RELOCATING_LABEL is bound there in no layer',
		]);
	});

	it("names a moved key whose new path no layer sets or binds at all", () => {
		expect(problems([relocating({ "legacy.gone": "gone" })], "fixture-relocating {}\n")).toEqual([
			'module "fixture-relocating": legacy.gone moves to fixture-relocating.gone, whose variable FIXTURE_RELOCATING_GONE is bound there in no layer',
		]);
	});

	it("names a new path declared bound to no variable that a layer binds", () => {
		expect(
			problems(
				[relocating({ "legacy.list": { to: "list", environmentVariable: null } })],
				`fixture-relocating {\n  list = []\n  list = \${?FIXTURE_RELOCATING_LIST}\n}\n`,
			),
		).toEqual([
			'module "fixture-relocating": legacy.list moves to fixture-relocating.list, declared bound to no variable, which FIXTURE_RELOCATING_LIST binds at fixture-relocating.list',
		]);
	});

	it("holds a path under a subtree declared without a variable to the more specific relocation that moves it", () => {
		const modules = [
			relocating({
				legacy: { to: "", environmentVariable: null },
				"legacy.retries": "retries",
			}),
		];
		expect(
			problems(
				modules,
				`fixture-relocating {\n  retries = \${?FIXTURE_RELOCATING_RETRIES}\n  list = []\n}\n`,
			),
		).toEqual([]);
		expect(problems(modules, "fixture-relocating {\n  retries = 3\n}\n")).toEqual([
			'module "fixture-relocating": legacy.retries moves to fixture-relocating.retries, whose variable FIXTURE_RELOCATING_RETRIES is bound there in no layer',
		]);
	});

	it("finds nothing wrong with core's own relocations and the JWKS module's, over core's reference.conf", () => {
		const reference = fileURLToPath(coreReference());
		expect(
			relocationBindingProblems({
				modules: [jwksModule],
				core: CORE_RELOCATIONS,
				layers: [reference],
				read: (path, env) => read(path, { OAUTH_JWT_ISSUER: "https://auth.test", ...env }),
				variables,
			}),
		).toEqual([]);
	});
});
