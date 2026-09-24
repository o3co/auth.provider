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
 * A stored `Code` is still accepted by `createCode`, for a consumer who turns
 * on `exactOptionalPropertyTypes` (#626).
 *
 * `createCode` took a parameter every field of which a `Code` has; a code
 * copied from one repository into another compiled. `CreateCodeInput` is now
 * derived from `Code`, whose fields are required keys holding `T | undefined`,
 * and keeps `expiresIn` optional: left out, the repository's default applies.
 * Under that option `a?: T` refuses an explicit `undefined`, so `expiresIn`
 * has to say `?: number | undefined` for a `Code` to be accepted. Without the
 * option the two spellings are the same type; this compiles a probe with the
 * option ON, and controls prove it is on and that the types resolved.
 */

import path from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { describe, expect, it } from "vitest";

const here = path.dirname(fileURLToPath(import.meta.url));
const repositorySource = path.resolve(here, "../CodeRepository.mts");
const typesSource = path.resolve(here, "../types.mts");

/** Compile one in-memory module next to the repository with exact optional properties on. */
const diagnosticsFor = (probe: string): readonly string[] => {
	const probePath = path.join(here, "__create_code_input_exact_optional_probe__.mts");
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

const importLine = `import type { CreateCodeInput } from ${JSON.stringify(repositorySource)};
import type { Code } from ${JSON.stringify(typesSource)};`;

describe("Code under exactOptionalPropertyTypes", () => {
	it("is accepted by createCode — a Code as a CreateCodeInput", () => {
		const diagnostics = diagnosticsFor(`${importLine}
declare const stored: Code;
export const input: CreateCodeInput = stored;
`);
		expect(diagnostics).toEqual([]);
	});

	it("still lets an input leave expiresIn out — the repository's default applies", () => {
		const diagnostics = diagnosticsFor(`${importLine}
declare const stored: Code;
const { code: _code, expiresIn: _expiresIn, ...rest } = stored;
export const input: CreateCodeInput = rest;
`);
		expect(diagnostics).toEqual([]);
	});

	it("is compiled with the option actually on — the control", () => {
		// `a?: string` refuses an explicit `undefined` only under the option. If
		// this compiled clean, the probes above would prove nothing.
		const diagnostics = diagnosticsFor(`${importLine}
type Plain = { readonly a?: string };
export const p: Plain = { a: undefined };
`);
		expect(diagnostics.join("\n")).toMatch(/exactOptionalPropertyTypes/);
	});

	it("resolves both types — a control against an import that silently became `any`", () => {
		// Diagnostics are read for the probe alone, so a type that resolved to
		// `any` elsewhere would leave the probes clean.
		const diagnostics = diagnosticsFor(`${importLine}
export const input: CreateCodeInput = { client_id: "c" };
export const stored: Code = { code: "x", client_id: "c", redirect_uri: "https://app.example/cb" };
`);
		const text = diagnostics.join("\n");
		expect(text).toMatch(/redirect_uri/);
		expect(text).toMatch(/grantedScope|code_challenge|nonce/);
	});
});
