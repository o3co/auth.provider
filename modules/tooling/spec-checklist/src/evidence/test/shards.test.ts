import { describe, expect, it } from "vitest";
import { parseItems } from "../../checklist.ts";
import { attemptsOf, legOf, legsOf, reportedOf, selectReports } from "../legs/legs.ts";
import type { EvidenceReport } from "../reporter.ts";
import { type Expected, itemStatuses, runsPrinted } from "../runs.ts";

const entry = "@mod/x#faults";
const identity = (extra: Partial<EvidenceReport["identity"]> = {}) => ({
	commit: "c1",
	run: "r1",
	attempt: 1,
	job: "faults",
	entry,
	target: "new" as const,
	...extra,
});
/** A report of the entry, of a shard or whole, its tests in `file` with the state given. */
const report = (
	shard: string | undefined,
	tests: { readonly file: string; readonly name: string; readonly state?: "passed" | "failed" }[],
	attempt = 1,
): EvidenceReport => ({
	identity: identity({ attempt, ...(shard ? { shard } : {}) }),
	errors: 0,
	tests: tests.map((t) => ({
		file: `modules/x/x/test/${t.file}`,
		names: [t.name],
		state: t.state ?? "passed",
	})),
});
const expected = (shards?: number): Expected => ({
	entries: [entry],
	areas: new Set(),
	runsOf: new Map(),
	suffixed: [{ entry, pkg: "@mod/x", files: ".faults.case.ts" }],
	noSkip: new Set(),
	gate: new Set(),
	shards: new Map(shards ? [[entry, shards]] : []),
});

describe("a run's shards", () => {
	it("are a whole number of at least two, where a run names them", () => {
		const run = { entry, kind: "faults", matrix: "@mod/x" };
		expect(runsPrinted("@mod/x", [{ ...run, shards: 3 }])).toEqual([{ ...run, shards: 3 }]);
		for (const shards of [1, 1.5, "2"])
			expect(() => runsPrinted("@mod/x", [{ ...run, shards }]), String(shards)).toThrow();
	});

	it("give a kind's jobs one leg each, one of one where a run has none, and refuse runs that disagree", () => {
		const runs = [
			{ entry, kind: "faults", matrix: "@mod/x", shards: 2 },
			{ entry: "@mod/y#faults", kind: "faults", matrix: "@mod/y" },
		];
		expect(legsOf(runs, "faults")).toEqual([
			{ matrix: "@mod/x", shard: "1/2" },
			{ matrix: "@mod/x", shard: "2/2" },
			{ matrix: "@mod/y", shard: "1/1" },
		]);
		expect(() =>
			legsOf([...runs, { entry: "@mod/x#more", kind: "faults", matrix: "@mod/x" }], "faults"),
		).toThrow("disagree");
	});

	it("keep a shard's reports when another shard alone is attempted again", () => {
		const runs = [{ entry, kind: "faults", matrix: "@mod/x", shards: 2 }];
		const mark = (attempt: number, shard: string) => ({
			attempted: { run: "r1", attempt, job: "faults", kind: "faults", matrix: "@mod/x", shard },
		});
		const attempts = attemptsOf([mark(1, "1/2"), mark(1, "2/2"), mark(2, "2/2")], runs, "r1");
		expect(attempts.get(legOf(entry, "1/2"))).toBe(1);
		expect(attempts.get(legOf(entry, "2/2"))).toBe(2);
		const first = report("1/2", [{ file: "a.faults.case.ts", name: "a" }]);
		const stale = report("2/2", [{ file: "b.faults.case.ts", name: "b" }]);
		const again = report("2/2", [{ file: "b.faults.case.ts", name: "b" }], 2);
		const kept = selectReports([first, stale, again], { commit: "c1", run: "r1" }, attempts);
		expect(kept).toEqual([first, again]);
	});

	it("report a run only with every shard, or whole, naming each shard missing, and leave out a report of another count", () => {
		const a = report("1/3", [{ file: "a.faults.case.ts", name: "a" }]);
		const c = report("3/3", [{ file: "c.faults.case.ts", name: "c" }]);
		const other = report("2/2", [{ file: "b.faults.case.ts", name: "b" }]);
		const partly = reportedOf([a, c, other], expected(3));
		expect([...partly.present, partly.missing, partly.reports]).toEqual([
			[`${entry} (shard 2/3)`],
			[a, c],
		]);
		const b = report("2/3", [{ file: "b.faults.case.ts", name: "b" }]);
		expect([...reportedOf([a, b, c], expected(3)).present]).toEqual([entry]);
		// A run made whole, as locally, or before runs had shards, stands for every shard.
		const whole = report(undefined, [{ file: "a.faults.case.ts", name: "a" }]);
		expect(reportedOf([whole], expected(3))).toMatchObject({
			present: new Set([entry]),
			missing: [],
		});
		expect(reportedOf([], expected(3)).missing).toEqual([entry]);
	});

	it("judge an item on every shard's reports together: each shard's file in its own, a missing shard incomplete, a failure in any failed", () => {
		const [item] = parseItems("rfc9999", "# X\n## 4 X\n- **rfc9999-4-a** MUST: a").items;
		const ref = (file: string, title: string) => ({
			pkg: "@mod/x",
			file: `test/${file}`,
			title,
			path: [title],
			suite: false,
		});
		const tests = new Map([
			[
				"rfc9999-4-a",
				[ref("a.faults.case.ts", "a [rfc9999-4-a]"), ref("b.faults.case.ts", "b [rfc9999-4-a]")],
			],
		]);
		const shard = (n: string, file: string, name: string, state?: "failed") =>
			report(n, [{ file, name, ...(state ? { state } : {}) }]);
		const of = (reports: EvidenceReport[]) =>
			itemStatuses(
				item ? [item] : [],
				tests,
				reports,
				expected(2),
				new Map([["@mod/x", "modules/x/x"]]),
			)[0];
		const one = shard("1/2", "a.faults.case.ts", "a [rfc9999-4-a]");
		const two = shard("2/2", "b.faults.case.ts", "b [rfc9999-4-a]");
		expect(of([one, two])).toMatchObject({ status: "passed", missing: [], unrun: [] });
		expect(of([one])).toMatchObject({ status: "incomplete" });
		const failed = shard("2/2", "b.faults.case.ts", "b [rfc9999-4-a]", "failed");
		expect(of([one, failed])).toMatchObject({ status: "failed" });
	});
});
