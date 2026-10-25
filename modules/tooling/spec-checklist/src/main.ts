import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { checklistFindings } from "./checklist.ts";
import {
	readChecklist,
	repoFindings,
	reportDir,
	repoRoot as root,
	updatedByOf,
	workspaceTests,
} from "./repo.ts";
import { reportFiles, summaryTable } from "./report.ts";
import { ledgerAgainstText } from "./text.ts";

const [command, ...args] = process.argv.slice(2);
const say = (line: string) => process.stdout.write(`${line}\n`);

if (command === "report") {
	const c = readChecklist();
	const files = reportFiles(c.specs, workspaceTests(root).tests, updatedByOf(c));
	mkdirSync(reportDir, { recursive: true });
	for (const [name, text] of files) writeFileSync(join(reportDir, name), text);
	say(`spec-checklist: wrote ${files.size} files to docs/compliance`);
} else if (command === "summary") {
	process.stdout.write(summaryTable(readChecklist().specs, workspaceTests(root).tests));
} else if (command === "check") {
	const found = repoFindings(readChecklist(), workspaceTests(root));
	for (const f of found) say(`${f.where}  ${f.detail}`);
	say(found.length === 0 ? "spec-checklist: ok" : `spec-checklist: ${found.length} finding(s)`);
	process.exitCode = found.length === 0 ? 0 : 1;
} else if (command === "ledger" && args.length === 2) {
	const [spec = "", file = ""] = args;
	const c = readChecklist();
	const ledger = c.specs.find((s) => s.spec === spec)?.ledger;
	// The checklist is held to its own rules first, so a ledger that breaks them never reads as matching.
	const broken = checklistFindings(c);
	for (const f of broken) say(`${f.where}  ${f.detail}`);
	if (broken.length > 0) {
		say(`spec-checklist: ${broken.length} finding(s) in the checklist; fix them before comparing`);
		process.exitCode = 1;
	} else if (!ledger) {
		say(`spec-checklist: ${spec} has no ledger`);
		process.exitCode = 1;
	} else {
		const bytes = readFileSync(file);
		const found = ledgerAgainstText(
			ledger,
			bytes.toString("utf8"),
			createHash("sha256").update(bytes).digest("hex"),
		);
		for (const f of found) say(`${spec}  ${f}`);
		say(
			found.length === 0
				? `spec-checklist: ${spec}'s ledger matches its text`
				: `spec-checklist: ${found.length} difference(s)`,
		);
		process.exitCode = found.length === 0 ? 0 : 1;
	}
} else {
	say("usage: report | summary | check | ledger <spec> <the spec's plain text file>");
	process.exitCode = 2;
}
