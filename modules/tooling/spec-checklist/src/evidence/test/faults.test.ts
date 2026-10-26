import { describe, expect, it } from "vitest";
import { parseItems } from "../../checklist.ts";
import type { TestRef } from "../../report.ts";
import type { EvidenceReport } from "../reporter.ts";
import {
	blocksRelease,
	complianceTable,
	type Expected,
	type ItemStatus,
	itemStatuses,
} from "../runs.ts";

const identity = (entry: string) => ({
	commit: "c1",
	run: "r1",
	attempt: 1,
	job: "faults",
	entry,
	target: "new" as const,
});
const pkg = "@mod/c";
const faultRun = `${pkg}#faults`;
const pkgDirs = new Map([[pkg, "modules/tooling/c"]]);
/** The fault run takes only the fault scenes' files and no skip; the area's own run, the rest. */
const expectedOf = (noSkip: boolean): Expected => ({
	entries: [pkg, faultRun],
	areas: new Set([pkg]),
	runsOf: new Map(),
	suffixed: [{ entry: faultRun, pkg, files: ".faults.case.ts" }],
	noSkip: new Set(noSkip ? [faultRun] : []),
	gate: new Set(),
});
const items = (faults = "Lr, F", mark = "") =>
	parseItems(
		"guarantee",
		`## 5 Once\n\n- **guarantee-5-a** MUST: once.\n  faults: ${faults}\n${mark}`,
	).items;
const ref = (title: string, faults: string[], file = "src/a.faults.case.ts"): TestRef => ({
	pkg,
	file,
	title,
	path: [title],
	suite: false,
	...(faults.length > 0 ? { faults } : {}),
});
const lr = ref("once {fault:Lr} [guarantee-5-a]", ["Lr"]);
const f = ref("once {fault:F} [guarantee-5-a]", ["F"]);
const plain = ref("once [guarantee-5-a]", [], "src/p.case.ts");
type State = EvidenceReport["tests"][number]["state"];
const ran = (entry: string, tests: [TestRef, State][]): EvidenceReport => ({
	identity: identity(entry),
	errors: 0,
	tests: tests.map(([r, state]) => ({
		file: `modules/tooling/c/${r.file}`,
		names: [r.title],
		state,
	})),
});
const statusOf = (
	refs: TestRef[],
	reports: EvidenceReport[],
	{ noSkip = true, faults = "Lr, F", mark = "" } = {},
) => {
	const [status] = itemStatuses(
		items(faults, mark),
		new Map([["guarantee-5-a", refs]]),
		reports,
		expectedOf(noSkip),
		pkgDirs,
	);
	if (!status) throw new Error("no status");
	return status;
};

describe("a guarantee's faults, each a column", () => {
	it("is passed only where every column's every test passed in every run of its file, and the item's other tests too", () => {
		const status = statusOf(
			[lr, f, plain],
			[
				ran(faultRun, [
					[lr, "passed"],
					[f, "passed"],
				]),
				ran(pkg, [[plain, "passed"]]),
			],
		);
		expect(status).toMatchObject({ status: "passed", holes: [], columns: [] });
	});

	it("is failed, not a hole, where a column failed beside one no test marks, keeping both", () => {
		const status = statusOf(
			[lr, plain],
			[ran(faultRun, [[lr, "failed"]]), ran(pkg, [[plain, "passed"]])],
		);
		expect(status.status).toBe("failed");
		expect(status.holes).toEqual(["F"]);
		expect(status.columns).toEqual([`${faultRun}: src/a.faults.case.ts > ${lr.title}: failed`]);
		expect(blocksRelease(status)).toBe(true);
		expect(complianceTable([status], [])).toContain(`- guarantee-5-a: no test marks F`);
		expect(complianceTable([status], [])).toContain(`- guarantee-5-a: ${status.columns?.[0]}`);
	});

	it("is a hole where a column has no test, and that stops a release", () => {
		const status = statusOf(
			[lr, plain],
			[ran(faultRun, [[lr, "passed"]]), ran(pkg, [[plain, "passed"]])],
		);
		expect(status).toMatchObject({ status: "hole", holes: ["F"] });
		expect(blocksRelease(status)).toBe(true);
	});

	it("is incomplete where a column's test has no result in a run of its file, or was skipped there", () => {
		const second = ref("again {fault:Lr} [guarantee-5-a]", ["Lr"]);
		const absent = statusOf(
			[lr, second, f, plain],
			[
				ran(faultRun, [
					[lr, "passed"],
					[f, "passed"],
				]),
				ran(pkg, [[plain, "passed"]]),
			],
		);
		expect(absent.status).toBe("incomplete");
		expect(absent.columns).toEqual([
			`${faultRun}: src/a.faults.case.ts > ${second.title}: no result`,
		]);
		for (const state of ["skipped", "pending"] as const) {
			const skipped = statusOf(
				[lr, f, plain],
				[
					ran(faultRun, [
						[lr, state],
						[f, "passed"],
					]),
					ran(pkg, [[plain, "passed"]]),
				],
				{ noSkip: false },
			);
			expect(skipped.status, state).toBe("incomplete");
			expect(skipped.columns, state).toEqual([
				`${faultRun}: src/a.faults.case.ts > ${lr.title}: ${state}`,
			]);
		}
	});

	it("is failed or incomplete where every column passed but another test naming the item failed or did not run", () => {
		const fault = ran(faultRun, [
			[lr, "passed"],
			[f, "passed"],
		]);
		const failed = statusOf([lr, f, plain], [fault, ran(pkg, [[plain, "failed"]])]);
		expect(failed).toMatchObject({ status: "failed", holes: [], columns: [] });
		expect(blocksRelease(failed)).toBe(true);
		const unrun = statusOf([lr, f, plain], [fault, ran(pkg, [])]);
		expect(unrun.status).toBe("incomplete");
		expect(unrun.unrun).toEqual([`${pkg}: src/p.case.ts > ${plain.title}`]);
		expect(blocksRelease(unrun)).toBe(true);
	});

	it("keeps its mark's status, and its findings, and a guarantee's noncompliant stops a release", () => {
		const status = statusOf([lr], [ran(faultRun, [[lr, "failed"]])], {
			mark: "  noncompliant: #1\n",
		});
		expect(status).toMatchObject({ status: "noncompliant", holes: ["F"] });
		expect(status.columns).toEqual([`${faultRun}: src/a.faults.case.ts > ${lr.title}: failed`]);
		expect(blocksRelease(status)).toBe(true);
	});

	it("leaves another spec's hole and noncompliant to release, as before", () => {
		const other = (status: ItemStatus["status"]): ItemStatus => ({
			id: "rfc8707-2-a",
			strength: "MUST",
			role: "as",
			status,
			passed: 0,
			failed: 0,
			missing: [],
			unrun: [],
			excused: {},
			evidence: [],
			failures: [],
		});
		expect(blocksRelease(other("hole"))).toBe(false);
		expect(blocksRelease(other("noncompliant"))).toBe(false);
		expect(blocksRelease(other("incomplete"))).toBe(true);
	});

	it("reads a suite's or a parameterized title as its tests', every result that matches", () => {
		const suite: TestRef = { ...ref("by %s {fault:Lr} [guarantee-5-a]", ["Lr"]), suite: true };
		const two = ran(faultRun, [[f, "passed"]]);
		const tests = [
			{
				file: "modules/tooling/c/src/a.faults.case.ts",
				names: ["by 1 {fault:Lr} [guarantee-5-a]", "one"],
				state: "passed" as const,
			},
			{
				file: "modules/tooling/c/src/a.faults.case.ts",
				names: ["by 2 {fault:Lr} [guarantee-5-a]", "two"],
				state: "failed" as const,
			},
		];
		const status = statusOf([suite, f], [{ ...two, tests: [...two.tests, ...tests] }], {
			faults: "Lr, F",
		});
		expect(status.status).toBe("failed");
	});
});
