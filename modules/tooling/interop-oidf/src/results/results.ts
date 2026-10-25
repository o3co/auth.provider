import { isDeepStrictEqual } from "node:util";
import type { Expected } from "../expected/expected.ts";

/** One entry of a suite test's log, as its API answers it. */
export interface LogEntry {
	readonly src?: string;
	readonly msg?: string;
	readonly result?: string;
	readonly blockId?: string;
	readonly startBlock?: boolean;
}

/** One test of a plan as it ran in the suite: none where it never ran. */
export interface ModuleRun {
	readonly testModule: string;
	readonly variant: Readonly<Record<string, string>>;
	readonly instance?: string;
	readonly info?: { readonly status: string; readonly result: string };
	readonly log: readonly LogEntry[];
}

/** What a suite test proved: an excused result counts neither way, nor does one a person must review. */
export type Outcome =
	| { readonly kind: "passed" }
	| { readonly kind: "failed"; readonly why: readonly string[] }
	| { readonly kind: "excused"; readonly class: string }
	| { readonly kind: "review" };

const kinds: Readonly<Record<string, Expected["expected-result"]>> = {
	FAILURE: "failure",
	WARNING: "warning",
};

/**
 * Each test's outcome, matching its failures and warnings to the expected entries as the suite's
 * runner does, but exactly: the test, its variant and the configuration file, then the block and
 * the condition. Entries no test used are named, as the runner fails them.
 */
export function outcomesOf(
	runs: readonly ModuleRun[],
	expected: {
		readonly configuration: string;
		readonly failures: readonly Expected[];
		readonly skips: readonly Expected[];
	},
): {
	readonly modules: readonly (ModuleRun & { readonly outcome: Outcome })[];
	readonly unused: readonly Expected[];
} {
	const used = new Set<Expected>();
	const forTest = (run: ModuleRun, entries: readonly Expected[]) =>
		entries.filter(
			(e) =>
				e["test-name"] === run.testModule &&
				e["configuration-filename"] === expected.configuration &&
				isDeepStrictEqual(e.variant, run.variant),
		);
	const outcome = (run: ModuleRun): Outcome => {
		if (run.info === undefined) return { kind: "failed", why: ["it never ran"] };
		if (run.info.status !== "FINISHED")
			return { kind: "failed", why: [`it ended ${run.info.status}`] };
		const failures = forTest(run, expected.failures);
		const blocks = new Map(
			run.log.flatMap((e) =>
				e.startBlock && e.blockId ? [[e.blockId, e.msg ?? ""] as const] : [],
			),
		);
		const unexpected: string[] = [];
		const excusedBy: Expected[] = [];
		for (const e of run.log) {
			const kind = kinds[e.result ?? ""];
			if (kind === undefined) continue;
			const blockName = e.blockId === undefined ? "" : (blocks.get(e.blockId) ?? "");
			const match = failures.find(
				(x) =>
					x["current-block"] === blockName &&
					x.condition === e.src &&
					x["expected-result"] === kind,
			);
			if (match === undefined) unexpected.push(`${e.result} ${blockName}: ${e.src}`);
			else excusedBy.push(match);
		}
		for (const x of excusedBy) used.add(x);
		if (unexpected.length > 0) return { kind: "failed", why: unexpected };
		if (run.info.result === "SKIPPED") {
			const skip = forTest(run, expected.skips)[0];
			if (skip === undefined) return { kind: "failed", why: ["skipped, and no entry expects it"] };
			used.add(skip);
			return { kind: "excused", class: skip.class };
		}
		// A person's review the suite asks for stands, whatever the expected warnings excuse.
		if (run.info.result === "REVIEW") return { kind: "review" };
		if (excusedBy.length > 0) return { kind: "excused", class: excusedBy[0]?.class ?? "" };
		if (run.info.result === "PASSED" || run.info.result === "WARNING") return { kind: "passed" };
		return { kind: "failed", why: [`its result is ${run.info.result}`] };
	};
	const modules = runs.map((run) => ({ ...run, outcome: outcome(run) }));
	return { modules, unused: [...expected.failures, ...expected.skips].filter((e) => !used.has(e)) };
}
