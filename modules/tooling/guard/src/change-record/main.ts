#!/usr/bin/env node
/** Writes the change record between two commits on standard output: `change-record <base> <head>`. */
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { readWorkspace } from "@mod/guard-imports";
import type { Budget } from "../contract.ts";
import { kindRules } from "../kinds.ts";
import { changeRecordOf, type Reading, readingOf } from "./record.ts";

const [base, head] = process.argv.slice(2);
if (base === undefined || head === undefined) {
	process.stderr.write("usage: change-record <base> <head>\n");
	process.exit(2);
}
const cwd = process.env.INIT_CWD ?? process.cwd();
const git = (args: string[], at = cwd) =>
	execFileSync("git", args, { cwd: at, encoding: "utf8" }).trim();
const repository = git(["rev-parse", "--show-toplevel"]);
const ownBudget = join(import.meta.dirname, "..", "..", "budget.json");
const budgetPath = relative(repository, ownBudget);

/** A commit read in a worktree of its own, on its own budget numbers (the current ones where it has none), then removed. */
function read(revision: string): Reading {
	const commit = git(["rev-parse", "--verify", `${revision}^{commit}`]);
	const tree = git(["rev-parse", `${commit}^{tree}`]);
	const dir = mkdtempSync(join(tmpdir(), "change-record-"));
	git(["worktree", "add", "--quiet", "--detach", dir, commit]);
	try {
		// The surfaces' types resolve through the installed links; nothing is run.
		execFileSync("pnpm", ["install", "--frozen-lockfile", "--prefer-offline", "--ignore-scripts"], {
			cwd: dir,
			stdio: ["ignore", "ignore", "inherit"],
		});
		const own = join(dir, budgetPath);
		const numbers = JSON.parse(readFileSync(existsSync(own) ? own : ownBudget, "utf8"));
		const budget = { ...numbers, ...kindRules } as Budget;
		return readingOf(readWorkspace(dir), budget, { commit, tree });
	} finally {
		git(["worktree", "remove", "--force", dir]);
		rmSync(dir, { recursive: true, force: true });
	}
}

process.stdout.write(changeRecordOf(read(base), read(head)));
