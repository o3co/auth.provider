import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { Pkg, Scope as ScopeOver } from "@mod/guard-imports";
import type { Budget } from "./contract.ts";

/** A package's units: itself, and each internal module (a directory with a card) apart from it. */
export function unitsOf(p: Pkg) {
	const cardDirs = p.files
		.filter((file) => file.endsWith("/README.md"))
		.map((file) => file.slice(0, -"/README.md".length));
	/** The innermost unit a file lies in; "" for the package itself. */
	const unitOf = (file: string) =>
		cardDirs.filter((dir) => file.startsWith(`${dir}/`)).sort((a, b) => b.length - a.length)[0] ??
		"";
	const cardOf = (unit: string) =>
		unit === "" ? p.card : readFileSync(join(p.dir, unit, "README.md"), "utf8");
	const whereOf = (unit: string) => (unit === "" ? p.name : `${p.name}/${unit}`);
	return { cardDirs, unitOf, cardOf, whereOf };
}

/** What every rule of guard reads, over its budget, and where it reports. */
export type Scope = ScopeOver<Budget>;
export { budgetsAsTest } from "@mod/guard-imports";
