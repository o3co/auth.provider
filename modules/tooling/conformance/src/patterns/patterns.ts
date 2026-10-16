import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type PatternSummary, patterns } from "@mod/create-app";

/** The pattern that is the full template, and full with every feature that opts in added. */
export const full = "full";
export const fullWithOptIns = `${full}+opt-ins`;

export interface Run {
	readonly pattern: string;
	readonly areas: readonly string[];
}

/** Each pattern on its areas, full twice; or the one pattern named, on the areas named. */
export function runsOf(summaries: readonly PatternSummary[], args: readonly string[]): Run[] {
	const all = summaries.flatMap(({ name, areas }) =>
		name === full
			? [
					{ pattern: name, areas },
					{ pattern: fullWithOptIns, areas },
				]
			: [{ pattern: name, areas }],
	);
	const [named, ...areas] = args;
	if (named === undefined) return all;
	const run = all.find((r) => r.pattern === named);
	if (!run) throw new Error(`${named}: no such pattern (${all.map((r) => r.pattern).join(", ")})`);
	return [{ pattern: named, areas: areas.length > 0 ? areas : run.areas }];
}

/** An ANSI escape sequence, as a terminal that colours output writes one (ESC, then CSI). */
const ansiEscape = new RegExp(`${String.fromCharCode(27)}\\[[0-?]*[ -/]*[@-~]`, "g");

/** An area's tests line with its scenes left out, failed on a failed test, an error or no tests. */
export function areaResult(output: string, code: number | null, leftOut: readonly string[]) {
	// Read as plain text, however the run coloured it.
	const tests = output
		.replace(ansiEscape, "")
		.match(/Tests {2}.*$/gm)
		?.at(-1);
	const counts = Map.groupBy(leftOut, (reason) => reason);
	return {
		failed: code !== 0 || !tests || tests.includes("failed"),
		line: `${tests ?? "no tests line"} | not-in-pattern ${leftOut.length}`,
		reasons: [...counts].map(([reason, all]) => `${all.length} ${reason}`),
	};
}

function runArea(pattern: string, area: string) {
	const file = join(mkdtempSync(join(tmpdir(), "conformance-left-out-")), "left-out");
	const ran = spawnSync("pnpm", ["--filter", `@mod/conformance-${area}`, "run", "conformance"], {
		encoding: "utf8",
		maxBuffer: 1 << 28,
		env: {
			...process.env,
			// Uncoloured, so the tests line reads alike wherever it runs.
			NO_COLOR: "1",
			FORCE_COLOR: "0",
			CONFORMANCE_TARGET: "new",
			CONFORMANCE_PATTERN: pattern,
			CONFORMANCE_NOT_IN_PATTERN_FILE: file,
		},
	});
	const left = (() => {
		try {
			return readFileSync(file, "utf8").split("\n").filter(Boolean);
		} catch {
			return [];
		}
	})();
	return areaResult(`${ran.stdout}${ran.stderr}`, ran.status, left);
}

/** Runs each pattern's areas on its app, writing each area's result; true when none failed and each had areas. */
export function runPatterns(
	args: readonly string[],
	summaries: readonly PatternSummary[] = patterns(),
	run: typeof runArea = runArea,
): boolean {
	let ok = true;
	for (const { pattern, areas } of runsOf(summaries, args)) {
		if (areas.length === 0) {
			ok = false;
			console.log(`${pattern}: no areas FAILED`);
		}
		for (const area of areas) {
			const result = run(pattern, area);
			ok &&= !result.failed;
			console.log(`${pattern} ${area}: ${result.line}${result.failed ? " FAILED" : ""}`);
			for (const reason of result.reasons) console.log(`  ${reason}`);
		}
	}
	return ok;
}

if (import.meta.main) process.exitCode = runPatterns(process.argv.slice(2)) ? 0 : 1;
