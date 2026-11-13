import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { Pkg } from "@mod/guard-imports";
import { expect, it } from "vitest";
import { packages, root } from "../../../test/root.ts";
import { wiringsFile, wiringsIn, wiringsOf } from "../wirings.ts";

const pkg = (name: string, manifest: Pkg["manifest"]): Pkg =>
	({ name, dir: `/w/${name}`, manifest, files: [] }) as unknown as Pkg;

it("holds the committed reference to what the wirings' manifests say", () => {
	expect(readFileSync(wiringsFile(root), "utf8")).toBe(wiringsOf(wiringsIn(packages)));
});

it("names in each row a workspace package, by the name its module is refused by", async () => {
	const rows = wiringsIn(packages);
	expect(rows.length).toBeGreaterThan(0);
	for (const row of rows) {
		// A `wires` that names no workspace package would send the operator nowhere.
		const owner = packages.find((p) => p.name === row.owner);
		expect(owner, `${row.owner}, which a wiring wires`).toBeDefined();
		// The refusal prints the module's own name: the one its definition gives, read as the reference reads routes.
		const entry = owner?.manifest.exports?.["./module"];
		expect(typeof entry, `${row.owner}'s ./module`).toBe("string");
		const { default: definition } = await import(join(owner?.dir ?? "", entry as string));
		expect((definition as { name: string }).name).toBe(row.module);
	}
});

it("keys a row by the package a wiring wires, listing every wiring of it in one row", () => {
	const rows = wiringsIn([
		pkg("@mod/b-store", { kind: "wiring", wires: "@mod/b" }),
		pkg("@mod/a-store", { kind: "wiring", wires: "@mod/a" }),
		pkg("@mod/a-other", { kind: "wiring", wires: "@mod/a" }),
		pkg("@mod/a", { kind: "feature", storeWiring: true }),
		pkg("@mod/c", { kind: "feature" }),
	]);
	expect(rows).toEqual([
		{ module: "a", owner: "@mod/a", wirings: ["@mod/a-other", "@mod/a-store"] },
		{ module: "b", owner: "@mod/b", wirings: ["@mod/b-store"] },
	]);
	const written = wiringsOf(rows);
	expect(written).toContain("| `a` | `@mod/a-other`, `@mod/a-store` |\n| `b` | `@mod/b-store` |\n");
	expect(written).toContain("`refused <module>: no module provides <contract>`");
	expect(written).not.toContain("](");
});
