import { describe, expect, it } from "vitest";
import { parseItems } from "../../checklist.ts";
import { expectedOf } from "../../repo.ts";
import { type EvidenceReport, entryOf } from "../reporter.ts";
import {
	attemptsOf,
	checkpoint,
	complianceTable,
	type Expected,
	entriesOfFile,
	itemStatuses,
	planOf,
	runsPrinted,
	selectReports,
} from "../runs.ts";

const identity = (entry: string, extra: Partial<EvidenceReport["identity"]> = {}) => ({
	commit: "c1",
	run: "r1",
	attempt: 1,
	job: "checks",
	entry,
	target: "new" as const,
	...extra,
});

describe("entryOf", () => {
	const root = "/repo";
	it("names the root's runs, an area's, a pattern's and a harness's", () => {
		expect(entryOf("/repo/vitest.config.ts", undefined, {}, root)).toBe("unit");
		expect(entryOf("/repo/vitest.integration.config.ts", undefined, {}, root)).toBe("integration");
		const area = "/repo/modules/tooling/conformance-code";
		expect(entryOf(`${area}/vitest.config.ts`, "@mod/conformance-code", {}, root)).toBe(
			"@mod/conformance-code",
		);
		expect(
			entryOf(
				`${area}/vitest.config.ts`,
				"@mod/conformance-code",
				{ CONFORMANCE_PATTERN: "simple-web" },
				root,
			),
		).toBe("@mod/conformance-code@simple-web");
		expect(
			entryOf(
				"/repo/modules/tooling/interop-oidf/vitest.config.ts",
				"@mod/interop-oidf",
				{ SPEC_EVIDENCE_RUN: "basic" },
				root,
			),
		).toBe("@mod/interop-oidf#basic");
	});
});

describe("a job's marks that it was attempted", () => {
	const runs = [
		{ entry: "unit", kind: "unit" },
		{ entry: "@mod/a@p", kind: "pattern", matrix: "p" },
		{ entry: "@mod/b@p", kind: "pattern", matrix: "p" },
		{ entry: "@mod/a@q", kind: "pattern", matrix: "q" },
	];
	const mark = (attempt: number, kind: string, matrix?: string, run = "r1") => ({
		attempted: { run, attempt, job: "j", kind, ...(matrix ? { matrix } : {}) },
	});

	it("give each run of the job the last attempt it was marked in, this run's marks alone", () => {
		const attempts = attemptsOf(
			[
				mark(1, "pattern", "p"),
				mark(2, "pattern", "p"),
				mark(1, "unit"),
				mark(9, "unit", undefined, "r0"),
			],
			runs,
			"r1",
		);
		expect(Object.fromEntries(attempts)).toEqual({ "@mod/a@p": 2, "@mod/b@p": 2, unit: 1 });
	});

	it("leave out an entry's reports older than its job's last attempt, and keep a job's not attempted again", () => {
		const earlier: EvidenceReport = { identity: identity("@mod/a@p"), tests: [], errors: 0 };
		const other: EvidenceReport = { identity: identity("@mod/a@q"), tests: [], errors: 0 };
		const kept = selectReports(
			[earlier, other],
			{ commit: "c1", run: "r1" },
			new Map([["@mod/a@p", 2]]),
		);
		expect(kept.map((r) => r.identity.entry)).toEqual(["@mod/a@q"]);
	});
});

describe("selectReports", () => {
	it("keeps every report of an entry and job's last attempt, in whatever order they come", () => {
		const passing: EvidenceReport = { identity: identity("unit"), tests: [], errors: 0 };
		const failing: EvidenceReport = { identity: identity("unit"), tests: [], errors: 1 };
		for (const order of [
			[passing, failing],
			[failing, passing],
		]) {
			const kept = selectReports(order, { commit: "c1", run: "r1" });
			expect(kept.map((r) => r.errors).sort()).toEqual([0, 1]);
		}
	});

	it("keeps the reports of this commit and run, the last attempt of each entry and job, and not the legacy target's", () => {
		const reports: EvidenceReport[] = [
			{ identity: identity("unit"), tests: [], errors: 0 },
			{ identity: identity("unit", { attempt: 2 }), tests: [], errors: 0 },
			{ identity: identity("unit", { commit: "c0" }), tests: [], errors: 0 },
			{ identity: identity("@mod/conformance-code", { target: "legacy" }), tests: [], errors: 0 },
			{ identity: identity("@mod/conformance-code"), tests: [], errors: 0 },
		];
		const kept = selectReports(reports, { commit: "c1", run: "r1" });
		expect(kept.map((r) => [r.identity.entry, r.identity.attempt])).toEqual([
			["unit", 2],
			["@mod/conformance-code", 1],
		]);
	});
});

describe("itemStatuses", () => {
	const items = parseItems(
		"rfc9999",
		[
			"# RFC 9999: Example",
			"## 4 X",
			"- **rfc9999-4-a** MUST: a",
			"- **rfc9999-4-b** MUST: b",
			"- **rfc9999-4-c** MUST: c",
			"- **rfc9999-4-d** MUST: d",
			"- **rfc9999-4-e** MUST: e",
			"- **rfc9999-4-f** MUST: f",
			"- **rfc9999-4-g** MUST: g",
			"  out-of-scope: not offered",
		].join("\n"),
	).items;
	const ref = (pkg: string, file: string, title: string) => ({ pkg, file, title });
	const tests = new Map([
		["rfc9999-4-a", [ref("@mod/x", "test/x.test.ts", "a [rfc9999-4-a]")]],
		[
			"rfc9999-4-b",
			[
				ref("@mod/x", "test/x.test.ts", "b one [rfc9999-4-b]"),
				ref("@mod/x", "test/x.test.ts", "b two [rfc9999-4-b]"),
			],
		],
		["rfc9999-4-c", [ref("@mod/conformance-code", "test/c.case.ts", "c [rfc9999-4-c]")]],
		["rfc9999-4-d", [ref("@mod/x", "test/d.test.ts", "d [rfc9999-4-d]")]],
		["rfc9999-4-e", [ref("@mod/x", "test/broken.test.ts", "e [rfc9999-4-e]")]],
	]);
	const expected: Expected = {
		entries: ["unit", "@mod/conformance-code", "@mod/conformance-code@simple-web"],
		areas: new Set(["@mod/conformance-code"]),
		runsOf: new Map(),
		suffixed: [],
		noSkip: new Set(),
	};
	const pkgDirs = new Map([
		["@mod/x", "modules/x/x"],
		["@mod/conformance-code", "modules/tooling/conformance-code"],
	]);
	const unit: EvidenceReport = {
		identity: identity("unit"),
		errors: 0,
		tests: [
			{ file: "modules/x/x/test/x.test.ts", names: ["a [rfc9999-4-a]"], state: "passed" },
			{ file: "modules/x/x/test/x.test.ts", names: ["b one [rfc9999-4-b]"], state: "passed" },
			{ file: "modules/x/x/test/x.test.ts", names: ["b two [rfc9999-4-b]"], state: "failed" },
			{
				file: "modules/x/x/test/d.test.ts",
				names: ["d [rfc9999-4-d]"],
				state: "skipped",
				note: "left out",
			},
			{ file: "modules/x/x/test/broken.test.ts", names: [], state: "failed" },
		],
	};
	const area: EvidenceReport = {
		identity: identity("@mod/conformance-code"),
		errors: 0,
		tests: [
			{
				file: "modules/tooling/conformance-code/test/c.case.ts",
				names: ["c [rfc9999-4-c]"],
				state: "passed",
			},
		],
	};

	it("is passed, failed, incomplete or unverified by the reports, and the mark or a hole without them", () => {
		const statuses = itemStatuses(items, tests, [unit, area], expected, pkgDirs);
		expect(Object.fromEntries(statuses.map((s) => [s.id, s.status]))).toEqual({
			"rfc9999-4-a": "passed",
			"rfc9999-4-b": "failed",
			// The pattern's report of conformance-code is missing.
			"rfc9999-4-c": "incomplete",
			"rfc9999-4-d": "unverified",
			// Its file failed to load: none of its tests ran.
			"rfc9999-4-e": "failed",
			"rfc9999-4-f": "hole",
			"rfc9999-4-g": "out-of-scope",
		});
	});

	it("keeps the identity of each report its tests ran in, with their results there, and its role", () => {
		const statuses = itemStatuses(items, tests, [unit, area], expected, pkgDirs);
		const of = (id: string) => statuses.find((s) => s.id === id);
		const at = { commit: "c1", run: "r1", attempt: 1, job: "checks" };
		expect(of("rfc9999-4-b")?.evidence).toEqual([
			{ ...at, entry: "unit", passed: 1, failed: 1, skipped: 0 },
		]);
		expect(of("rfc9999-4-c")?.evidence).toEqual([
			{ ...at, entry: "@mod/conformance-code", passed: 1, failed: 0, skipped: 0 },
		]);
		expect(of("rfc9999-4-f")?.evidence).toEqual([]);
		expect(of("rfc9999-4-a")?.role).toBe("as");
	});

	it("keeps the report and the reason of a failure no test owns: a file that did not load, a run's own error", () => {
		const at = { commit: "c1", run: "r1", attempt: 1, job: "checks" };
		const [, , , , e] = itemStatuses(items, tests, [unit, area], expected, pkgDirs);
		expect(e).toMatchObject({ id: "rfc9999-4-e", status: "failed", evidence: [] });
		expect(e?.failures).toEqual([
			{ ...at, entry: "unit", reason: "modules/x/x/test/broken.test.ts: failed outside its tests" },
		]);
		const erred: EvidenceReport = { ...area, errors: 2 };
		const [, , c] = itemStatuses(items, tests, [unit, erred], expected, pkgDirs);
		expect(c).toMatchObject({ id: "rfc9999-4-c", status: "failed" });
		expect(c?.failures).toEqual([
			{ ...at, entry: "@mod/conformance-code", reason: "2 error(s) no test owns" },
		]);
		expect(itemStatuses(items, tests, [unit, area], expected, pkgDirs)[0]?.failures).toEqual([]);
	});

	it("counts the checkpoint by class and status, and by role", () => {
		const statuses = itemStatuses(items, tests, [unit, area], expected, pkgDirs);
		const counts = checkpoint(statuses);
		expect(counts.MUST).toMatchObject({ passed: 1, failed: 2, incomplete: 1, hole: 1 });
		expect(counts.byRole.as).toEqual({ MUST: counts.MUST, SHOULD: counts.SHOULD });
		expect(counts.byRole.rp?.MUST.passed).toBe(0);
		expect(complianceTable(statuses, [])).toContain(
			"| as | MUST | 1 | 2 | 1 | 1 | 1 | 0 | 0 | 1 |",
		);
	});

	it("counts a test once for an item its suite and itself both name", () => {
		const twice: EvidenceReport = {
			identity: identity("unit"),
			errors: 0,
			tests: [
				{
					file: "modules/x/x/test/x.test.ts",
					names: ["a suite [rfc9999-4-a]", "a [rfc9999-4-a]"],
					state: "passed",
				},
			],
		};
		const [a] = itemStatuses(
			items.slice(0, 1),
			tests,
			[twice],
			{ ...expected, entries: ["unit"] },
			pkgDirs,
		);
		expect(a).toMatchObject({ status: "passed", passed: 1 });
		expect(a?.evidence.map((e) => e.passed)).toEqual([1]);
	});

	it("does not count a test the harness excused as passed, nor as failed", () => {
		const excused: EvidenceReport = {
			identity: identity("unit"),
			errors: 0,
			tests: [
				{
					file: "modules/x/x/test/x.test.ts",
					names: ["a [rfc9999-4-a]"],
					state: "skipped",
					note: "excused: adaptation",
				},
			],
		};
		const [a] = itemStatuses(
			items.slice(0, 1),
			tests,
			[excused],
			{ ...expected, entries: ["unit"] },
			pkgDirs,
		);
		expect(a).toMatchObject({
			id: "rfc9999-4-a",
			status: "unverified",
			excused: { adaptation: 1 },
		});
	});
});

describe("the runs a package prints", () => {
	it("are taken as a list of runs, and anything else refused naming the package", () => {
		const printed = [{ entry: "@mod/x@p", kind: "pattern", matrix: "p" }];
		expect(runsPrinted("@mod/x", printed)).toEqual(printed);
		expect(() => runsPrinted("@mod/x", ["@mod/x@p"])).toThrow(
			"@mod/x: its evidence-runs printed what is not a list of runs",
		);
		expect(() => runsPrinted("@mod/x", [{ entry: "e", kind: "k", releaseOnly: false }])).toThrow();
	});

	it("give each kind of job the values its matrix takes, each once", () => {
		const runs = [
			{ entry: "@mod/a@p1", kind: "pattern", matrix: "p1" },
			{ entry: "@mod/b@p1", kind: "pattern", matrix: "p1" },
			{ entry: "@mod/a@p2", kind: "pattern", matrix: "p2" },
			{ entry: "@mod/a", kind: "area", matrix: "@mod/a" },
		];
		expect(planOf(runs, "pattern")).toEqual(["p1", "p2"]);
		expect(planOf(runs, "none")).toEqual([]);
	});
});

describe("a run's files and its rule on skips", () => {
	const runs = [
		{ entry: "unit", kind: "unit" },
		{ entry: "@mod/keys", kind: "area", matrix: "@mod/keys" },
		{ entry: "@mod/keys@p", kind: "pattern", matrix: "p" },
		{
			entry: "@mod/keys#faults",
			kind: "fault",
			matrix: "@mod/keys",
			files: ".faults.ts",
			noSkip: true as const,
		},
	];
	const expected = expectedOf(runs, false);

	it("are taken as a run's own fields, and refused when not a suffix or not true", () => {
		expect(runsPrinted("@mod/keys", runs)).toEqual(runs);
		expect(() => runsPrinted("@mod/keys", [{ entry: "e", kind: "k", files: 1 }])).toThrow();
		expect(() => runsPrinted("@mod/keys", [{ entry: "e", kind: "k", noSkip: false }])).toThrow();
	});

	it("send a file to the runs whose suffix it bears, and every other file by the default rules", () => {
		expect(entriesOfFile("@mod/keys", "test/store.faults.ts", expected)).toEqual([
			"@mod/keys#faults",
		]);
		expect(entriesOfFile("@mod/keys", "test/keys.case.ts", expected)).toEqual([
			"@mod/keys",
			"@mod/keys@p",
		]);
		expect(entriesOfFile("@mod/keys", "test/keys.test.ts", expected)).toEqual(["unit"]);
	});

	it("fail an item whose test was skipped, excused or not, in a run that takes no skip", () => {
		const [a] = parseItems("rfc9999", "# X\n## 4 X\n- **rfc9999-4-a** MUST: a").items;
		const tests = new Map([
			[
				"rfc9999-4-a",
				[{ pkg: "@mod/keys", file: "test/store.faults.ts", title: "a [rfc9999-4-a]" }],
			],
		]);
		const faults: EvidenceReport = {
			identity: identity("@mod/keys#faults"),
			errors: 0,
			tests: [
				{
					file: "modules/k/keys/test/store.faults.ts",
					names: ["a [rfc9999-4-a]"],
					state: "skipped",
					note: "excused: adaptation",
				},
			],
		};
		const [status] = itemStatuses(
			a ? [a] : [],
			tests,
			[faults],
			expected,
			new Map([["@mod/keys", "modules/k/keys"]]),
		);
		expect(status).toMatchObject({ status: "failed" });
		expect(status?.failures.map((f) => f.reason)).toEqual([
			"modules/k/keys/test/store.faults.ts > a [rfc9999-4-a]: skipped in a run that takes no skip",
		]);
	});
});

describe("each test of an item, in each run of its file", () => {
	it("leaves the item incomplete where a run reported without one of its tests, naming it", () => {
		const [a] = parseItems("rfc9999", "# X\n## 4 X\n- **rfc9999-4-a** MUST: a").items;
		const ref = (title: string) => ({ pkg: "@mod/x", file: "test/x.test.ts", title });
		const tests = new Map([
			["rfc9999-4-a", [ref("one [rfc9999-4-a]"), ref("a suite [rfc9999-4-a]")]],
		]);
		const report = (names: string[][]): EvidenceReport => ({
			identity: identity("unit"),
			errors: 0,
			tests: names.map((n) => ({
				file: "modules/x/x/test/x.test.ts",
				names: n,
				state: "passed" as const,
			})),
		});
		const of = (r: EvidenceReport) =>
			itemStatuses(
				a ? [a] : [],
				tests,
				[r],
				{ entries: ["unit"], areas: new Set(), runsOf: new Map(), suffixed: [], noSkip: new Set() },
				new Map([["@mod/x", "modules/x/x"]]),
			)[0];
		// The suite's title is met by a test inside it.
		expect(of(report([["one [rfc9999-4-a]"], ["a suite [rfc9999-4-a]", "inside"]]))).toMatchObject({
			status: "passed",
			unrun: [],
		});
		expect(of(report([["one [rfc9999-4-a]"]]))).toMatchObject({
			status: "incomplete",
			unrun: ["unit: test/x.test.ts > a suite [rfc9999-4-a]"],
		});
	});
});

describe("the runs a suffix owns", () => {
	it("are no area's or pattern's for a file that does not bear the suffix", () => {
		const expected = expectedOf(
			[
				{ entry: "@mod/keys", kind: "area", matrix: "@mod/keys" },
				{ entry: "@mod/keys@p", kind: "pattern", matrix: "p", files: ".special.case.ts" },
			],
			false,
		);
		expect(entriesOfFile("@mod/keys", "test/ordinary.case.ts", expected)).toEqual(["@mod/keys"]);
		expect(entriesOfFile("@mod/keys", "test/a.special.case.ts", expected)).toEqual(["@mod/keys@p"]);
	});

	it("keep their files where only a release makes the run and the run is no release's", () => {
		const expected = expectedOf(
			[
				{ entry: "@mod/keys", kind: "area", matrix: "@mod/keys" },
				{
					entry: "@mod/keys#release",
					kind: "release",
					files: ".release.ts",
					releaseOnly: true as const,
				},
			],
			false,
		);
		expect(entriesOfFile("@mod/keys", "test/x.release.ts", expected)).toEqual([
			"@mod/keys#release",
		]);
		expect(expected.entries).toEqual(["@mod/keys"]);
	});
});

describe("a test's results, matched to its title in the source", () => {
	const [a] = parseItems("rfc9999", "# X\n## 4 X\n- **rfc9999-4-a** MUST: a").items;
	const ref = (title: string) => ({ pkg: "@mod/x", file: "test/x.test.ts", title });
	const expected: Expected = {
		entries: ["unit"],
		areas: new Set(),
		runsOf: new Map(),
		suffixed: [],
		noSkip: new Set(),
	};
	const report = (names: string[][]): EvidenceReport => ({
		identity: identity("unit"),
		errors: 0,
		tests: names.map((n) => ({
			file: "modules/x/x/test/x.test.ts",
			names: n,
			state: "passed" as const,
		})),
	});
	const of = (title: string, reports: EvidenceReport[]) =>
		itemStatuses(
			a ? [a] : [],
			new Map([["rfc9999-4-a", [ref(title)]]]),
			reports,
			expected,
			new Map([["@mod/x", "modules/x/x"]]),
		)[0];

	it("meets a parameterized title by the names it expands to: printf forms and a table's properties", () => {
		expect(
			of("case %s [rfc9999-4-a]", [report([["case 1 [rfc9999-4-a]"], ["case 2 [rfc9999-4-a]"]])]),
		).toMatchObject({ status: "passed", unrun: [] });
		expect(
			of("suite %d, %# [rfc9999-4-a]", [report([["suite 1, 0 [rfc9999-4-a]", "inside"]])]),
		).toMatchObject({ status: "passed", unrun: [] });
		expect(
			of("with $user.name and $id [rfc9999-4-a]", [report([["with alice and 7 [rfc9999-4-a]"]])]),
		).toMatchObject({ status: "passed", unrun: [] });
		expect(of("100%% sure [rfc9999-4-a]", [report([["100% sure [rfc9999-4-a]"]])])).toMatchObject({
			status: "passed",
		});
		expect(of("case %s [rfc9999-4-a]", [report([["another [rfc9999-4-a]"]])])).toMatchObject({
			status: "incomplete",
		});
	});

	it("is looked for in each report of the run that ran its file, not in any one of them", () => {
		const both = [report([["one [rfc9999-4-a]"]]), report([["other test"]])];
		expect(of("one [rfc9999-4-a]", both)).toMatchObject({
			status: "incomplete",
			unrun: ["unit: test/x.test.ts > one [rfc9999-4-a]"],
		});
		expect(
			of("one [rfc9999-4-a]", [report([["one [rfc9999-4-a]"]]), report([["one [rfc9999-4-a]"]])]),
		).toMatchObject({ status: "passed" });
	});
});
