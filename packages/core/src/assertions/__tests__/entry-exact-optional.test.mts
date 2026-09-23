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
 * `list()` into `add()` compiles for a consumer who turns on
 * `exactOptionalPropertyTypes`.
 *
 * The stored entry carries `undefined` for a ceiling it does not name, and
 * under that option `a?: T` refuses an explicit `undefined` — so the input's
 * optional fields have to say `?: T | undefined` for the stored form to be
 * accepted back. Without the option the two spellings are the same type, so
 * no ordinary type test can tell them apart; this compiles a probe with the
 * option ON, and a control proves it is on.
 */

import path from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { describe, expect, it } from "vitest";

const here = path.dirname(fileURLToPath(import.meta.url));
const registrySource = path.resolve(here, "../issuerRegistry.mts");

/** Compile one in-memory module next to the registry with exact optional properties on. */
const diagnosticsFor = (probe: string): readonly string[] => {
	const probePath = path.join(here, "__exact_optional_probe__.mts");
	const options: ts.CompilerOptions = {
		strict: true,
		exactOptionalPropertyTypes: true,
		noEmit: true,
		skipLibCheck: true,
		target: ts.ScriptTarget.ES2022,
		module: ts.ModuleKind.NodeNext,
		moduleResolution: ts.ModuleResolutionKind.NodeNext,
		allowImportingTsExtensions: true,
		types: [],
	};
	const host = ts.createCompilerHost(options);
	const readFile = host.readFile.bind(host);
	const fileExists = host.fileExists.bind(host);
	const getSourceFile = host.getSourceFile.bind(host);
	host.readFile = (f) => (f === probePath ? probe : readFile(f));
	host.fileExists = (f) => f === probePath || fileExists(f);
	host.getSourceFile = (f, lang, onError, create) =>
		f === probePath
			? ts.createSourceFile(f, probe, lang, true, ts.ScriptKind.TS)
			: getSourceFile(f, lang, onError, create);
	const program = ts.createProgram([probePath], options, host);
	return ts
		.getPreEmitDiagnostics(program, program.getSourceFile(probePath))
		.map((d) => ts.flattenDiagnosticMessageText(d.messageText, "\n"));
};

const importLine = `import type { AssertionIssuerEntry, AssertionIssuerEntryInput } from ${JSON.stringify(registrySource)};`;

describe("AssertionIssuerEntry under exactOptionalPropertyTypes", () => {
	it("is accepted back as input — list() into add() compiles", () => {
		const diagnostics = diagnosticsFor(`${importLine}
declare const stored: AssertionIssuerEntry;
export const input: AssertionIssuerEntryInput = stored;
`);
		expect(diagnostics).toEqual([]);
	});

	it("is compiled with the option actually on — the control", () => {
		// `a?: string` refuses an explicit `undefined` only under the option. If
		// this compiled clean, the probe above would prove nothing.
		const diagnostics = diagnosticsFor(`${importLine}
type Plain = { readonly a?: string };
export const p: Plain = { a: undefined };
`);
		expect(diagnostics.join("\n")).toMatch(/exactOptionalPropertyTypes/);
	});
});
