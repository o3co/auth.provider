import { join } from "node:path";
import { type Item, type Role, roles } from "../checklist.ts";
import { classOf, itemId } from "../ids.ts";
import type { TestRef } from "../report.ts";
import type { EvidenceReport } from "./reporter.ts";

/** A run a CI run makes: its report's entry, its job's kind and matrix value, and whether only a release makes it. */
export interface Run {
	readonly entry: string;
	readonly kind: string;
	readonly matrix?: string;
	readonly releaseOnly?: true;
	/** The test files it runs, by the suffix of their names; unset, the default rules say which. */
	readonly files?: string;
	/** A test of it that is skipped, excused or not, or left todo, fails its items. */
	readonly noSkip?: true;
}

/** A package's printed runs, each checked to be a run; a value that is not refused naming the package. */
export function runsPrinted(pkg: string, printed: unknown): Run[] {
	const isRun = (r: unknown): r is Run => {
		const o = r as Partial<Run> | null;
		return (
			typeof o?.entry === "string" &&
			typeof o.kind === "string" &&
			(o.matrix === undefined || typeof o.matrix === "string") &&
			(o.releaseOnly === undefined || o.releaseOnly === true) &&
			(o.files === undefined || (typeof o.files === "string" && o.files !== "")) &&
			(o.noSkip === undefined || o.noSkip === true)
		);
	};
	if (!Array.isArray(printed) || !printed.every(isRun))
		throw new Error(`${pkg}: its evidence-runs printed what is not a list of runs`);
	return printed;
}

/** The values a kind of job's matrix takes, each once, in the order the runs give them. */
export const planOf = (runs: readonly Run[], kind: string): string[] => [
	...new Set(
		runs.filter((r) => r.kind === kind && r.matrix !== undefined).map((r) => r.matrix ?? ""),
	),
];

/** The runs a CI run must report, and which of them run a package's tests. */
export interface Expected {
	readonly entries: readonly string[];
	/** The packages whose `.case.ts` tests run as their own entry and once per pattern (`<package>@<pattern>`). */
	readonly areas: ReadonlySet<string>;
	/** A harness's runs (`<package>#<run>`) that name no files, by its package. */
	readonly runsOf: ReadonlyMap<string, readonly string[]>;
	/** The runs that name their files by a suffix, with their package. */
	readonly suffixed: readonly {
		readonly entry: string;
		readonly pkg: string;
		readonly files: string;
	}[];
	/** The runs that take no skip. */
	readonly noSkip: ReadonlySet<string>;
}

export type RunStatus =
	| "out-of-scope"
	| "noncompliant"
	| "deviates"
	| "hole"
	| "failed"
	| "incomplete"
	| "unverified"
	| "passed";

/** A report a test naming an item ran in: its identity, and the results of the item's tests in it. */
export interface Evidence {
	readonly commit: string;
	readonly run: string;
	readonly attempt: number;
	readonly job: string;
	readonly entry: string;
	readonly passed: number;
	readonly failed: number;
	readonly skipped: number;
}

/** A failure no test naming the item owns, as a report gave it: its identity and the reason. */
export interface Failure {
	readonly commit: string;
	readonly run: string;
	readonly attempt: number;
	readonly job: string;
	readonly entry: string;
	readonly reason: string;
}

export interface ItemStatus {
	readonly id: string;
	readonly strength: Item["strength"];
	readonly role: Role;
	readonly status: RunStatus;
	readonly passed: number;
	readonly failed: number;
	/** The expected runs of its tests that did not report. */
	readonly missing: readonly string[];
	/** Its tests absent from a run of their file that reported, as `<entry>: <file> > <title>`. */
	readonly unrun: readonly string[];
	/** Results a harness excused, by their class. */
	readonly excused: Readonly<Record<string, number>>;
	/** The reports its tests ran in, the status's provenance. */
	readonly evidence: readonly Evidence[];
	/** The failures of its tests' files and runs that no test owns, with the reports that gave them. */
	readonly failures: readonly Failure[];
}

/** A job's mark that it was attempted, written before it can fail: the run, the attempt, and the runs it makes. */
export interface Attempted {
	readonly attempted: {
		readonly run: string;
		readonly attempt: number;
		readonly job: string;
		readonly kind: string;
		readonly matrix?: string;
	};
}

/** The last attempt of this run that each entry's job was marked attempted in, by the runs the marks name. */
export function attemptsOf(marks: readonly Attempted[], runs: readonly Run[], run: string) {
	const last = new Map<string, number>();
	for (const { attempted: a } of marks.filter((m) => m.attempted.run === run)) {
		const named = runs.filter((r) => r.kind === a.kind && r.matrix === a.matrix);
		for (const r of named) last.set(r.entry, Math.max(last.get(r.entry) ?? 0, a.attempt));
	}
	return last;
}

/**
 * Of the reports given, this commit's and run's for the new system, all of each entry and job's last
 * attempt, and none older than the last attempt its job was marked in: a job that failed before it
 * reported leaves its earlier attempt's evidence behind.
 */
export function selectReports(
	reports: readonly EvidenceReport[],
	of: { readonly commit: string; readonly run: string },
	attempted: ReadonlyMap<string, number> = new Map(),
): EvidenceReport[] {
	const ours = reports.filter(
		(r) =>
			r.identity.commit === of.commit &&
			r.identity.run === of.run &&
			r.identity.target === "new" &&
			r.identity.attempt >= (attempted.get(r.identity.entry) ?? 0),
	);
	const keyOf = (r: EvidenceReport) => JSON.stringify([r.identity.entry, r.identity.job]);
	const lastAttempt = new Map<string, number>();
	for (const r of ours)
		lastAttempt.set(keyOf(r), Math.max(lastAttempt.get(keyOf(r)) ?? 0, r.identity.attempt));
	// Every report of the last attempt: two processes of one entry, job and attempt both count.
	return ours.filter((r) => r.identity.attempt === lastAttempt.get(keyOf(r)));
}

/** The expected runs a test file's tests run in. */
export function entriesOfFile(pkg: string, file: string, expected: Expected): readonly string[] {
	if (file.endsWith(".integration.test.ts")) return ["integration"];
	const named = expected.suffixed.filter((r) => r.pkg === pkg && file.endsWith(r.files));
	if (named.length > 0) return named.map((r) => r.entry);
	const runs = expected.runsOf.get(pkg);
	if (runs) return runs;
	// An area's own run and its pattern runs, but those a suffix owns, which only their files reach.
	const owned = new Set(expected.suffixed.map((r) => r.entry));
	if (file.endsWith(".case.ts") && expected.areas.has(pkg))
		return expected.entries.filter((e) => (e === pkg || e.startsWith(`${pkg}@`)) && !owned.has(e));
	if (file.endsWith(".test.ts")) return ["unit"];
	return [pkg];
}

/**
 * Whether a name a report gives is the title written in the source: a parameterized title's printf
 * forms (`%s`, `%d`, `%#` and the rest) and a table's `$property` stand for what they expanded to.
 */
export function titleMatches(title: string, name: string): boolean {
	if (title === name) return true;
	const parts = title.split(/(%%|%[sdifjoOc#]|\$[A-Za-z_]\w*(?:\.\w+)*)/);
	const pattern = parts
		.map((p, k) =>
			k % 2 === 0 ? p.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") : p === "%%" ? "%" : ".*?",
		)
		.join("");
	return new RegExp(`^${pattern}$`, "s").test(name);
}

/** The items a test's names give, each once however many of its names give it. */
const idsIn = (names: readonly string[]) => [
	...new Set(
		names
			.flatMap((n) => [...n.matchAll(/\[([^\]\s]+)\]/g)].map((m) => m[1] ?? ""))
			.filter((id) => itemId.test(id)),
	),
];

/** Each item's status from the reports, in the order the card's invariant gives; an excused result counted apart. */
export function itemStatuses(
	items: readonly Item[],
	tests: ReadonlyMap<string, readonly TestRef[]>,
	reports: readonly EvidenceReport[],
	expected: Expected,
	pkgDirs: ReadonlyMap<string, string>,
): ItemStatus[] {
	const present = new Set(reports.map((r) => r.identity.entry));
	const errored = new Set(reports.filter((r) => r.errors > 0).map((r) => r.identity.entry));
	const brokenFiles = new Set(
		reports.flatMap((r) =>
			r.tests.filter((t) => t.names.length === 0 && t.state === "failed").map((t) => t.file),
		),
	);
	const seen = new Map<
		string,
		{ passed: number; failed: number; excused: Record<string, number> }
	>();
	const evidence = new Map<string, Map<EvidenceReport, Evidence>>();
	for (const r of reports) {
		for (const t of r.tests) {
			for (const id of idsIn(t.names)) {
				const byReport = evidence.get(id) ?? new Map<EvidenceReport, Evidence>();
				const { commit, run, attempt, job, entry } = r.identity;
				const e = byReport.get(r) ?? {
					commit,
					run,
					attempt,
					job,
					entry,
					passed: 0,
					failed: 0,
					skipped: 0,
				};
				const state = t.state === "pending" ? "skipped" : t.state;
				byReport.set(r, { ...e, [state]: e[state] + 1 });
				evidence.set(id, byReport);
			}
		}
	}
	for (const t of reports.flatMap((r) => r.tests)) {
		for (const id of idsIn(t.names)) {
			const s = seen.get(id) ?? { passed: 0, failed: 0, excused: {} };
			const excuse = /^excused: (\S+)/.exec(t.note ?? "")?.[1];
			if (t.state === "passed") s.passed += 1;
			else if (t.state === "failed") s.failed += 1;
			else if (t.state === "skipped" && excuse) s.excused[excuse] = (s.excused[excuse] ?? 0) + 1;
			seen.set(id, s);
		}
	}
	return items.map((i) => {
		const refs = tests.get(i.id) ?? [];
		const s = seen.get(i.id) ?? { passed: 0, failed: 0, excused: {} };
		const files = refs.map((r) => join(pkgDirs.get(r.pkg) ?? r.pkg, r.file));
		const entries = [...new Set(refs.flatMap((r) => entriesOfFile(r.pkg, r.file, expected)))];
		const missing = entries.filter((e) => expected.entries.includes(e) && !present.has(e));
		const broken = files.some((f) => brokenFiles.has(f)) || entries.some((e) => errored.has(e));
		// Each test naming the item, in each report of each run of its file that reported: a suite's title
		// is met by a test in it; a run none of whose reports ran the file lacks it too.
		const unrun = refs.flatMap((ref) => {
			const path = join(pkgDirs.get(ref.pkg) ?? ref.pkg, ref.file);
			// A test's names hold its path's; a suite's, its path's and then a test's inside it.
			const meets = (names: readonly string[]) =>
				(ref.suite ? names.length > ref.path.length : names.length === ref.path.length) &&
				ref.path.every((s, k) => s === null || titleMatches(s, names[k] ?? ""));
			const ran = (r: EvidenceReport) => r.tests.some((t) => t.file === path && meets(t.names));
			return entriesOfFile(ref.pkg, ref.file, expected)
				.filter((e) => present.has(e))
				.filter((e) => {
					const covering = reports.filter(
						(r) => r.identity.entry === e && r.tests.some((t) => t.file === path),
					);
					return covering.length === 0 || !covering.every(ran);
				})
				.map((e) => `${e}: ${ref.file} > ${ref.title}`);
		});
		const failures = reports.flatMap((r) => {
			const { commit, run, attempt, job, entry } = r.identity;
			const at = { commit, run, attempt, job, entry };
			const outside = [
				...new Set(
					r.tests
						.filter((t) => t.names.length === 0 && t.state === "failed" && files.includes(t.file))
						.map((t) => t.file),
				),
			].map((file) => ({ ...at, reason: `${file}: failed outside its tests` }));
			const errors =
				r.errors > 0 && entries.includes(entry)
					? [{ ...at, reason: `${r.errors} error(s) no test owns` }]
					: [];
			const skipped = expected.noSkip.has(entry)
				? r.tests
						.filter(
							(t) =>
								(t.state === "skipped" || t.state === "pending") && idsIn(t.names).includes(i.id),
						)
						.map((t) => ({
							...at,
							reason: `${t.file} > ${t.names.join(" > ")}: skipped in a run that takes no skip`,
						}))
				: [];
			return [...outside, ...errors, ...skipped];
		});
		const refusedSkip = failures.some((f) =>
			f.reason.endsWith("skipped in a run that takes no skip"),
		);
		const status: RunStatus =
			i.mark?.kind ??
			(refs.length === 0
				? "hole"
				: s.failed > 0 || broken || refusedSkip
					? "failed"
					: missing.length > 0 || unrun.length > 0
						? "incomplete"
						: s.passed > 0
							? "passed"
							: "unverified");
		const provenance = [...(evidence.get(i.id)?.values() ?? [])];
		return {
			id: i.id,
			strength: i.strength,
			role: i.role,
			status,
			...s,
			missing,
			unrun,
			evidence: provenance,
			failures,
		};
	});
}

const order: readonly RunStatus[] = [
	"passed",
	"failed",
	"incomplete",
	"unverified",
	"hole",
	"noncompliant",
	"deviates",
	"out-of-scope",
];

const countsOf = (statuses: readonly ItemStatus[]) => {
	const of = (cls: "MUST" | "SHOULD") =>
		Object.fromEntries(
			order.map((st) => [
				st,
				statuses.filter((s) => classOf(s.strength) === cls && s.status === st).length,
			]),
		);
	return { MUST: of("MUST"), SHOULD: of("SHOULD") };
};

/** The counts the checkpoint reports: by strength's class and status, every item counted once, and by role. */
export function checkpoint(statuses: readonly ItemStatus[]) {
	const byRole = Object.fromEntries(
		roles.map((role) => [role, countsOf(statuses.filter((s) => s.role === role))]),
	);
	return { ...countsOf(statuses), byRole };
}

/** The run's compliance table, as Markdown. */
export function complianceTable(
	statuses: readonly ItemStatus[],
	missingRuns: readonly string[],
): string {
	const counts = checkpoint(statuses);
	return [
		"# Compliance of this run",
		"",
		missingRuns.length === 0
			? "Every expected run reported."
			: `Runs that did not report: ${missingRuns.join(", ")}.`,
		"",
		`| Class | ${order.join(" | ")} |`,
		`|---|${order.map(() => "---").join("|")}|`,
		...(["MUST", "SHOULD"] as const).map(
			(cls) => `| ${cls} | ${order.map((st) => counts[cls][st]).join(" | ")} |`,
		),
		"",
		`| Role | Class | ${order.join(" | ")} |`,
		`|---|---|${order.map(() => "---").join("|")}|`,
		...roles.flatMap((role) =>
			(["MUST", "SHOULD"] as const).map(
				(cls) =>
					`| ${role} | ${cls} | ${order.map((st) => counts.byRole[role]?.[cls][st] ?? 0).join(" | ")} |`,
			),
		),
		"",
		"| Item | Strength | Status | Passed | Failed | Missing runs | Excused |",
		"|---|---|---|---|---|---|---|",
		...statuses.map(
			(s) =>
				`| ${s.id} | ${s.strength} | ${s.status} | ${s.passed} | ${s.failed} | ${s.missing.join(", ")} | ${Object.entries(
					s.excused,
				)
					.map(([k, n]) => `${k} ${n}`)
					.join(", ")} |`,
		),
		"",
	].join("\n");
}
