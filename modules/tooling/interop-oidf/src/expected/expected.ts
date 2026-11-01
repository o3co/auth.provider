import { readFile } from "node:fs/promises";
import { join } from "node:path";
import {
	type Decision,
	type ExceptionEntry,
	exceptionProblems,
	type Item,
	type Ledger,
	readChecklist,
} from "@mod/spec-checklist";

/** A result of the suite's the harness expects, as written in the package: the suite's fields and its class. */
export interface Expected extends ExceptionEntry {
	readonly "test-name": string;
	readonly variant: Readonly<Record<string, string>>;
	readonly "configuration-filename": string;
	/** A failure's or warning's; a skip names none. */
	readonly "current-block"?: string;
	readonly condition?: string;
	readonly "expected-result"?: "failure" | "warning";
}

/** The fields the suite's runner reads. */
const suiteFields = [
	"test-name",
	"variant",
	"configuration-filename",
	"current-block",
	"condition",
	"expected-result",
] as const;

/** Characters the runner's matching reads as a pattern. */
const wildcard = /[*?[\]]/;

/** A variant with its keys in one order: the outcomes match a variant whatever order it is written in. */
const canonical = (variant: unknown) =>
	typeof variant === "object" && variant !== null
		? Object.fromEntries(Object.entries(variant).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)))
		: variant;

const testOf = (e: Expected) =>
	JSON.stringify([e["test-name"], canonical(e.variant), e["configuration-filename"]]);

/** A skip whose test a failure names under another class: one test's entries share one class across both files. */
const acrossFiles = (failures: readonly Expected[], skips: readonly Expected[]) => {
	const classes = new Map(failures.map((e) => [testOf(e), e.class]));
	return skips.flatMap((e) => {
		const other = classes.get(testOf(e));
		return other === undefined || !e.class || other === e.class
			? []
			: [
					`${e["test-name"]} (${e["configuration-filename"]}): a test's entries share one class, here ${other} and ${e.class}`,
				];
	});
};

/**
 * Why the entries may not go to the suite: each names its test, variant and configuration file
 * exactly, a failure its block and condition too, once; its class holds as the checklist judges
 * it; and one test's entries share one class, which its result is excused by.
 */
export function expectedProblems(
	entries: readonly Expected[],
	kind: "failure" | "skip",
	known: {
		readonly items: ReadonlyMap<string, Item>;
		readonly decisions: ReadonlyMap<string, Decision>;
		readonly ledgers?: ReadonlyMap<string, Ledger>;
	},
): string[] {
	const problems: string[] = [];
	const seen = new Set<string>();
	const classes = new Map<string, string>();
	for (const e of entries) {
		const at = `${e["test-name"]} (${e["configuration-filename"]})`;
		for (const field of ["test-name", "configuration-filename"] as const) {
			if (typeof e[field] !== "string" || e[field] === "" || wildcard.test(e[field]))
				problems.push(`${at}: ${field} is written out, without a wildcard`);
		}
		if (typeof e.variant !== "object" || e.variant === null)
			problems.push(`${at}: variant is the test's own, written out`);
		if (kind === "failure") {
			// A failure outside any block is logged with the empty block, which names it exactly.
			if (typeof e["current-block"] !== "string")
				problems.push(`${at}: current-block is written out`);
			for (const field of ["condition", "expected-result"] as const) {
				if (!e[field]) problems.push(`${at}: ${field} is written out`);
			}
		}
		if (!e.class) {
			problems.push(`${at}: names no class`);
			continue;
		}
		problems.push(...exceptionProblems(e, known).map((p) => `${at}: ${p}`));
		const key = JSON.stringify(
			suiteFields.map((f) => (f === "variant" ? canonical(e.variant) : (e[f] ?? null))),
		);
		if (seen.has(key)) problems.push(`${at}: written twice`);
		seen.add(key);
		const other = classes.get(testOf(e));
		if (other !== undefined && other !== e.class)
			problems.push(`${at}: a test's entries share one class, here ${other} and ${e.class}`);
		classes.set(testOf(e), e.class);
	}
	return problems;
}

/** The entries as the suite's runner takes them: its own fields alone. */
export function suiteEntries(entries: readonly Expected[]): Record<string, unknown>[] {
	return entries.map((e) =>
		Object.fromEntries(suiteFields.flatMap((f) => (e[f] === undefined ? [] : [[f, e[f]]]))),
	);
}

/**
 * The expected entries of the plan `name`, read from `dir` (`<name>.failures.json` and
 * `<name>.skips.json`) and judged against the checklist: the plan is refused, before the suite
 * starts, where any may not be taken.
 */
export async function expectedOf(
	dir: string,
	name: string,
): Promise<{ readonly failures: Expected[]; readonly skips: Expected[] }> {
	const checklist = readChecklist();
	const known = {
		items: new Map(checklist.specs.flatMap((s) => s.items.map((i) => [i.id, i] as const))),
		decisions: checklist.decisions,
		ledgers: new Map(
			checklist.specs.flatMap((s) => (s.ledger ? [[s.spec, s.ledger] as const] : [])),
		),
	};
	const read = async (kind: string) =>
		JSON.parse(await readFile(join(dir, `${name}.${kind}.json`), "utf8")) as Expected[];
	const failures = await read("failures");
	const skips = await read("skips");
	const problems = [
		...expectedProblems(failures, "failure", known),
		...expectedProblems(skips, "skip", known),
		...acrossFiles(failures, skips),
	];
	if (problems.length > 0)
		throw new Error(`the expected entries of ${name} may not be taken:\n${problems.join("\n")}`);
	return { failures, skips };
}
