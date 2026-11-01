import { symlinkSync } from "node:fs";
import { join } from "node:path";
import { expect, it } from "vitest";
import { scopeOf } from "../src/contract.ts";
import { budget, pkg } from "./workspace.ts";

const scope = (...packages: Parameters<typeof scopeOf>[0]) =>
	scopeOf(packages, budget, () => undefined);

it("answers a source file's facts, read by one lexical program over every package's sources", () => {
	const a = pkg(
		"@f/a",
		{ "src/contract.ts": 'import { b } from "@f/b";\nexport const a = b;\n' },
		{},
	);
	const b = pkg("@f/b", { "src/contract.ts": "export const b = 1;\n" }, {});
	const s = scope(a, b);
	const facts = s.factsOf(a, "src/contract.ts");
	expect(facts.edges.map((e) => [e.form, e.specifier.text, e.target.kind])).toEqual([
		["import", "@f/b", "package"],
	]);
	expect(s.factsOf(a, "src/contract.ts")).toBe(facts);
	expect(s.factsOf(b, "src/contract.ts").edges).toEqual([]);
});

it("keeps what a manifest declares apart from what the source is seen to reach", () => {
	const a = pkg(
		"@g/a",
		{ "src/contract.ts": 'import "@g/b";\n' },
		{ dependencies: { "@g/c": "*" } },
	);
	const b = pkg("@g/b", { "src/contract.ts": "" }, {});
	const c = pkg("@g/c", { "src/contract.ts": "" }, {});
	const s = scope(a, b, c);
	expect(s.workspaceDeps(a, true)).toEqual(["@g/c"]);
	expect(s.factsOf(a, "src/contract.ts").edges.map((e) => e.specifier.text)).toEqual(["@g/b"]);
});

it("tells the package whose directory holds a path, its links followed, and none outside every package", () => {
	const a = pkg("@o/a", { "src/contract.ts": "" }, {});
	const b = pkg("@o/b", { "src/contract.ts": "" }, {});
	symlinkSync(join(b.dir, "src"), join(a.dir, "linked"));
	const s = scope(a, b);
	expect(s.ownerOf(join(a.dir, "src", "contract.ts"))?.name).toBe("@o/a");
	expect(s.ownerOf(join(a.dir, "linked", "contract.ts"))?.name).toBe("@o/b");
	expect(s.ownerOf(join(a.dir, "..", "elsewhere.ts"))).toBeUndefined();
});
