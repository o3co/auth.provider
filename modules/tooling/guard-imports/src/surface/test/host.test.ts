import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import ts from "typescript";
import { expect, it } from "vitest";
import { host } from "../host.ts";

it("parses a file again only when its text changed: the same path with another text is another file", () => {
	const path = join(mkdtempSync(join(tmpdir(), "surface-host-")), "read.ts");
	const read = () => host.getSourceFile(path, ts.ScriptTarget.ES2022);
	writeFileSync(path, "export const a = 1;\n");
	const first = read();
	expect(read()).toBe(first);
	writeFileSync(path, "export const a = 2;\n");
	const changed = read();
	expect(changed).not.toBe(first);
	expect(changed?.text).toBe("export const a = 2;\n");
	expect(read()).toBe(changed);
});
