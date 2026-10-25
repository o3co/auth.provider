import { readFileSync } from "node:fs";
import { join } from "node:path";
import { readWorkspace } from "@mod/guard-imports";
import { type Budget, branchingImports, check, heavyDependencyCards } from "./contract.ts";
import { kindRules } from "./kinds.ts";
import { readDocuments } from "./workspace.ts";

const root = process.env.INIT_CWD ?? process.cwd();
const budget = {
	...JSON.parse(readFileSync(join(import.meta.dirname, "..", "budget.json"), "utf8")),
	...kindRules,
} as Budget;
const packages = readWorkspace(root);
const violations = check(packages, budget, readDocuments(root));
// Reported, not refused: an internal module pulling in what the rest of its package does not.
for (const { where, packages: alone } of branchingImports(packages, budget)) {
	process.stdout.write(`measure  dependency branch  ${where}  ${alone.join(", ")}\n`);
}
// Reported, not refused: a unit's dependency cards grow with cards it does not own.
for (const { where, bytes } of heavyDependencyCards(packages, budget)) {
	process.stdout.write(
		`measure  dependency cards  ${where}  ${bytes} > ${budget.dependencyCardBytes}\n`,
	);
}
for (const v of violations) process.stdout.write(`${v.rule}  ${v.where}  ${v.detail}\n`);
process.stdout.write(
	violations.length === 0 ? "guard: ok\n" : `guard: ${violations.length} violation(s)\n`,
);
process.exit(violations.length === 0 ? 0 : 1);
