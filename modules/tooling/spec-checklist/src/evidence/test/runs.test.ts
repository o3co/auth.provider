import { describe, expect, it } from "vitest";
import { parseItems } from "../../checklist.ts";
import { type EvidenceReport, entryOf } from "../reporter.ts";
import {
	checkpoint,
	complianceTable,
	type Expected,
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
