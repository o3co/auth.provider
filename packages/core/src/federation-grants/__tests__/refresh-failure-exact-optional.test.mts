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
 * A stored refresh-failure stamp is still accepted where a report is, for a
 * consumer who turns on `exactOptionalPropertyTypes` (#626).
 *
 * The stamp used to extend the report type. It names its optional fields as
 * required keys holding `T | undefined` now, and under that option `a?: T`
 * refuses an explicit `undefined` — so the report's optional fields have to
 * say `?: T | undefined` for the stamp to be accepted. Without the option the
 * two spellings are the same type, so no ordinary type test can tell them
 * apart; this compiles a probe with the option ON, and controls prove it is
 * on and that the types resolved.
 */

import path from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { describe, expect, it } from "vitest";

const here = path.dirname(fileURLToPath(import.meta.url));
const typesSource = path.resolve(here, "../types.mts");

/** Compile one in-memory module next to the types with exact optional properties on. */
const diagnosticsFor = (probe: string): readonly string[] => {
	const probePath = path.join(here, "__refresh_failure_exact_optional_probe__.mts");
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

const importLine = `import type { FederationGrantRefreshFailure, FederationGrantRefreshFailureInput } from ${JSON.stringify(typesSource)};`;

describe("FederationGrantRefreshFailure under exactOptionalPropertyTypes", () => {
	it("is accepted where a report is — the stamp as a FederationGrantRefreshFailureInput", () => {
		const diagnostics = diagnosticsFor(`${importLine}
declare const stamp: FederationGrantRefreshFailure;
export const report: FederationGrantRefreshFailureInput = stamp;
`);
		expect(diagnostics).toEqual([]);
	});

	it("still lets a report leave both fields out — widened, not made required", () => {
		const diagnostics = diagnosticsFor(`${importLine}
export const report: FederationGrantRefreshFailureInput = { at: new Date(), kind: "unavailable" };
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

	it("resolves both types — a control against an import that silently became `any`", () => {
		// Diagnostics are read for the probe alone, so an import that failed to
		// resolve elsewhere would leave both types `any` and the probe clean.
		const diagnostics = diagnosticsFor(`${importLine}
export const report: FederationGrantRefreshFailureInput = { at: new Date(), kind: "no-such-kind" };
export const stamp: FederationGrantRefreshFailure = { at: new Date(), kind: "rejected", count: 1 };
`);
		const text = diagnostics.join("\n");
		expect(text).toMatch(/"no-such-kind"/);
		expect(text).toMatch(/retryAfterSeconds/);
	});
});
