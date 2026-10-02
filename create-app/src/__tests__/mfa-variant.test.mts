/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */
import {
	existsSync,
	mkdirSync,
	mkdtempSync,
	readdirSync,
	readFileSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { applyMfaVariant, twinTarget, variantText } from "../internal/mfa-variant.mjs";

const BEGIN = "# no-mfa:omit-begin";
const END = "# no-mfa:omit-end";

describe("variantText", () => {
	const marked = ["kept", BEGIN, "mfa only", "more mfa", END, "kept too", ""].join("\n");

	it("leaves a file with no marker as it is, with MFA and without", () => {
		expect(variantText("a\nb\n", true, "f")).toBe("a\nb\n");
		expect(variantText("a\nb\n", false, "f")).toBe("a\nb\n");
	});

	it("drops a marked block, its marker lines included, without MFA", () => {
		expect(variantText(marked, false, "f")).toBe("kept\nkept too\n");
	});

	it("keeps a marked block and drops only its marker lines with MFA", () => {
		expect(variantText(marked, true, "f")).toBe("kept\nmfa only\nmore mfa\nkept too\n");
	});

	it("reads a marker in any comment syntax: the line holding the token is the marker", () => {
		const html = ["a", "<!-- no-mfa:omit-begin -->", "b", "<!-- no-mfa:omit-end -->", ""].join(
			"\n",
		);
		const ts = ["a", "\t// no-mfa:omit-begin", "b", "\t// no-mfa:omit-end", ""].join("\n");
		expect(variantText(html, false, "f")).toBe("a\n");
		expect(variantText(ts, false, "f")).toBe("a\n");
		expect(variantText(ts, true, "f")).toBe("a\nb\n");
	});

	it("omits a file marked whole without MFA, and drops only the marker line with MFA", () => {
		const whole = "// no-mfa:omit-file\nexport {};\n";
		expect(variantText(whole, false, "f")).toBeUndefined();
		expect(variantText(whole, true, "f")).toBe("export {};\n");
	});

	it.each([
		{ case: "a begin with no end", text: `a\n${BEGIN}\nb\n` },
		{ case: "an end with no begin", text: `a\n${END}\nb\n` },
		{ case: "a begin inside a block", text: `${BEGIN}\n${BEGIN}\n${END}\n${END}\n` },
		{ case: "a token it does not know", text: "a\n# no-mfa:omit-start\nb\n" },
	])("refuses $case, naming the file, with MFA and without", ({ text }) => {
		expect(() => variantText(text, false, "config/x.conf")).toThrow(/config\/x\.conf/);
		expect(() => variantText(text, true, "config/x.conf")).toThrow(/config\/x\.conf/);
	});
});

describe("twinTarget", () => {
	it.each([
		["mfaSwitch.no-mfa.mts", "mfaSwitch.mts"],
		["mfa-switch.test.no-mfa.mts", "mfa-switch.test.mts"],
		["Dockerfile.no-mfa", "Dockerfile"],
	])("names %s the twin of %s", (twin, target) => {
		expect(twinTarget(twin)).toBe(target);
	});

	it.each(["mfaSwitch.mts", "no-mfa.mts", "x.no-mfa-ish.mts", ".no-mfa"])(
		"names %s the twin of nothing",
		(name) => {
			expect(twinTarget(name)).toBeUndefined();
		},
	);
});

describe("applyMfaVariant", () => {
	let dir: string;

	const write = (path: string, content: string): void => {
		mkdirSync(join(dir, path, ".."), { recursive: true });
		writeFileSync(join(dir, path), content);
	};
	const read = (path: string): string => readFileSync(join(dir, path), "utf-8");

	beforeEach(() => {
		dir = mkdtempSync(join(tmpdir(), "create-auth-provider-variant-"));
		write("src/switch.mts", 'import "mfa";\n');
		write("src/switch.no-mfa.mts", "export {};\n");
		write("src/__tests__/switch-redis.test.mts", "// no-mfa:omit-file\nexport {};\n");
		write("config/app.conf", `a = 1\n${BEGIN}\nmfa = 2\n${END}\n`);
		write("plain.txt", "untouched\n");
	});

	afterEach(() => {
		rmSync(dir, { recursive: true, force: true });
	});

	it("without MFA: puts each twin in place of its target, omits what is marked, and keeps the rest", () => {
		applyMfaVariant(dir, false);
		expect(read("src/switch.mts")).toBe("export {};\n");
		expect(existsSync(join(dir, "src/switch.no-mfa.mts"))).toBe(false);
		expect(existsSync(join(dir, "src/__tests__/switch-redis.test.mts"))).toBe(false);
		expect(read("config/app.conf")).toBe("a = 1\n");
		expect(read("plain.txt")).toBe("untouched\n");
	});

	it("with MFA: drops each twin, keeps its target, and drops only the marker lines", () => {
		applyMfaVariant(dir, true);
		expect(read("src/switch.mts")).toBe('import "mfa";\n');
		expect(readdirSync(join(dir, "src")).sort()).toEqual(["__tests__", "switch.mts"]);
		expect(read("src/__tests__/switch-redis.test.mts")).toBe("export {};\n");
		expect(read("config/app.conf")).toBe("a = 1\nmfa = 2\n");
		expect(read("plain.txt")).toBe("untouched\n");
	});

	it("refuses a twin whose target is not there, with MFA and without, before changing anything", () => {
		write("src/orphan.no-mfa.mts", "export {};\n");
		expect(() => applyMfaVariant(dir, false)).toThrow(/src\/orphan\.no-mfa\.mts/);
		expect(() => applyMfaVariant(dir, true)).toThrow(/src\/orphan\.no-mfa\.mts/);
		expect(read("src/switch.mts")).toBe('import "mfa";\n');
		expect(read("config/app.conf")).toBe(`a = 1\n${BEGIN}\nmfa = 2\n${END}\n`);
	});

	it("refuses an unbalanced marker before changing anything", () => {
		write("config/broken.conf", `${BEGIN}\nx = 1\n`);
		expect(() => applyMfaVariant(dir, false)).toThrow(/config\/broken\.conf/);
		expect(read("src/switch.mts")).toBe('import "mfa";\n');
		expect(existsSync(join(dir, "src/__tests__/switch-redis.test.mts"))).toBe(true);
	});
});
