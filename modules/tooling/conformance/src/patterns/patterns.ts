import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
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

/** The pattern of every run, `full+opt-ins` included, as JSON may list them for a job each. */
export const patternNames = (summaries: readonly PatternSummary[]) =>
	runsOf(summaries, []).map((run) => run.pattern);

/** Each area's run on each pattern's app, as `<area's package>@<pattern>`: the runs a CI run reports. */
export const evidenceRuns = (summaries: readonly PatternSummary[]) =>
	runsOf(summaries, []).flatMap((run) =>
		run.areas.map((area) => `@mod/conformance-${area}@${run.pattern}`),
	);

/** An ANSI escape sequence, as a terminal that colours output writes one (ESC, then CSI). */
const ansiEscape = new RegExp(`${String.fromCharCode(27)}\\[[0-?]*[ -/]*[@-~]`, "g");

/** What a failed area's output tells of why: vitest's failures from their heading on, or its last lines. */
export function failureOf(output: string): string {
	const lines = output.replace(ansiEscape, "").trimEnd().split("\n");
	const heading = lines.findIndex((line) => /Failed (Suites|Tests) \d+/.test(line));
	return (heading === -1 ? lines.slice(-60) : lines.slice(heading, heading + 400)).join("\n");
}

/** An area's tests line with its scenes left out, failed on a failed test, an error or no tests; a failed one tells why. */
export function areaResult(output: string, code: number | null, leftOut: readonly string[]) {
	// Read as plain text, however the run coloured it.
	const tests = output
		.replace(ansiEscape, "")
		.match(/Tests {2}.*$/gm)
		?.at(-1);
	const counts = Map.groupBy(leftOut, (reason) => reason);
	const failed = code !== 0 || !tests || tests.includes("failed");
	return {
		failed,
		line: `${tests ?? "no tests line"} | not-in-pattern ${leftOut.length}`,
		reasons: [...counts].map(([reason, all]) => `${all.length} ${reason}`),
		...(failed ? { told: failureOf(output) } : {}),
	};
}

/** An area's result, with where a failed one's whole output is kept. */
type AreaRun = ReturnType<typeof areaResult> & { readonly kept?: string };

function runArea(pattern: string, area: string): AreaRun {
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
	const output = `${ran.stdout}${ran.stderr}`;
	const result = areaResult(output, ran.status, left);
	if (!result.failed) return result;
	// Kept whole, so a failure is read without running the area again.
	const kept = join(mkdtempSync(join(tmpdir(), `conformance-${pattern}-${area}-`)), "output.log");
	writeFileSync(kept, output);
	return { ...result, kept };
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
			if (result.told) console.log(result.told.replace(/^/gm, "  "));
			if (result.kept) console.log(`  whole output: ${result.kept}`);
		}
	}
	return ok;
}

if (import.meta.main) {
	const args = process.argv.slice(2);
	if (args[0] === "--list") console.log(JSON.stringify(patternNames(patterns())));
	else if (args[0] === "--evidence-runs") console.log(JSON.stringify(evidenceRuns(patterns())));
	else process.exitCode = runPatterns(args) ? 0 : 1;
}
