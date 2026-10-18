import { readFileSync } from "node:fs";
import { join } from "node:path";
import { type Budget, branchingImports, check } from "./contract.ts";
import { kindRules } from "./kinds.ts";
import { pendingLimits } from "./pending/pending.ts";
import { readDocuments, readWorkspace } from "./workspace.ts";

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
// Reported, not refused yet: the limits that become G7's once nothing is over them.
for (const { where, detail } of pendingLimits(packages, budget)) {
	process.stdout.write(`measure  ${where}  ${detail}\n`);
}
for (const v of violations) process.stdout.write(`${v.rule}  ${v.where}  ${v.detail}\n`);
process.stdout.write(
	violations.length === 0 ? "guard: ok\n" : `guard: ${violations.length} violation(s)\n`,
);
process.exit(violations.length === 0 ? 0 : 1);
