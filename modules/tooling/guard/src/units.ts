import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { Budget } from "./contract.ts";
import type { Pkg } from "./workspace.ts";

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

/** What every rule reads, and where it reports. */
export interface Scope {
	readonly packages: readonly Pkg[];
	readonly budget: Budget;
	readonly byName: ReadonlyMap<string, Pkg>;
	readonly report: (rule: string, where: string, detail: string) => void;
	/** A package's kind, as its manifest names it. */
	readonly kindOf: (p: Pkg) => string;
	/** A kind's place in the kind order; -1 for none or an unknown one. */
	readonly level: (p: Pkg) => number;
	readonly isCommon: (p: Pkg) => boolean;
	readonly isTest: (file: string) => boolean;
	readonly sources: (p: Pkg) => string[];
	readonly workspaceDeps: (p: Pkg, dev: boolean) => string[];
}

export function scopeOf(packages: readonly Pkg[], budget: Budget, report: Scope["report"]): Scope {
	const byName = new Map(packages.map((p) => [p.name, p]));
	const kindOf = (p: Pkg) => p.manifest.kind ?? "";
	const conventional = new RegExp(budget.testFile);
	return {
		packages,
		budget,
		byName,
		report,
		kindOf,
		level: (p) => budget.kindOrder.findIndex((kinds) => kinds.includes(kindOf(p))),
		isCommon: (p) => kindOf(p) === budget.commonKind,
		isTest: (file) => conventional.test(file),
		sources: (p) => p.files.filter((f) => f.endsWith(".ts") && !f.endsWith(".config.ts")),
		workspaceDeps: (p, dev) =>
			Object.keys({
				...p.manifest.dependencies,
				...(dev ? p.manifest.devDependencies : {}),
			}).filter((name) => byName.has(name)),
	};
}

/**
 * A published contract test suite is test code for the budget, though it lives outside the test
 * place and is still checked as shipped code by every other rule.
 */
export function budgetsAsTest(s: Scope, p: Pkg, file: string) {
	return s.isTest(file) || file === p.manifest.exports?.["./testing"]?.replace(/^\.\//, "");
}
