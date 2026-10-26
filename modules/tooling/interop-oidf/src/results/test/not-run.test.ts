import { describe, expect, it } from "vitest";
import type { Expected } from "../../expected/expected.ts";
import { type ModuleRun, outcomesOf } from "../results.ts";

const variant = { client_auth_type: "client_secret_basic", response_type: "code" };
const other = { client_auth_type: "client_secret_post", response_type: "code" };
const never = (testModule: string, v = variant): ModuleRun => ({ testModule, variant: v, log: [] });
const ran = (testModule: string): ModuleRun => ({
	testModule,
	variant,
	instance: `${testModule}-1`,
	info: { status: "FINISHED", result: "PASSED" },
	log: [],
});
const skip = (testModule: string, v = variant): Expected =>
	({
		"test-name": testModule,
		variant: v,
		"configuration-filename": "rp.json",
		class: "optional",
		spec: "oidc-core",
		section: "5.3",
	}) as Expected;

const judged = (
	runs: ModuleRun[],
	skips: Expected[],
	notRun: { testModule: string; variant: Record<string, string> }[],
) => outcomesOf(runs, { configuration: "rp.json", failures: [], skips, notRun });

describe("a test its driver declared not run", () => {
	it("is excused by the skip entry that names it, the entry used, where both the driver and the entry say so", () => {
		const entry = skip("oidcc-client-test");
		const out = judged(
			[never("oidcc-client-test")],
			[entry],
			[{ testModule: "oidcc-client-test", variant }],
		);
		expect(out.modules[0]?.outcome).toEqual({ kind: "excused", class: "optional" });
		expect(out.unused).toEqual([]);
	});

	it("fails where only the driver says so, no entry excusing it", () => {
		const out = judged(
			[never("oidcc-client-test")],
			[],
			[{ testModule: "oidcc-client-test", variant }],
		);
		expect(out.modules[0]?.outcome).toEqual({
			kind: "failed",
			why: ["declared not run, and no entry excuses it"],
		});
	});

	it("fails as never run where only an entry names it, the driver declaring nothing", () => {
		const entry = skip("oidcc-client-test");
		const out = judged([never("oidcc-client-test")], [entry], []);
		expect(out.modules[0]?.outcome).toEqual({ kind: "failed", why: ["it never ran"] });
		expect(out.unused).toEqual([entry]);
	});

	it("fails where it ran though the driver declared it not run", () => {
		const entry = skip("oidcc-client-test");
		const out = judged(
			[ran("oidcc-client-test")],
			[entry],
			[{ testModule: "oidcc-client-test", variant }],
		);
		expect(out.modules[0]?.outcome).toEqual({
			kind: "failed",
			why: ["declared not run, but it ran"],
		});
	});

	it("is the test of its variant alone, whatever order its keys are in", () => {
		const entry = skip("oidcc-client-test");
		const reordered = { response_type: "code", client_auth_type: "client_secret_basic" };
		const out = judged(
			[never("oidcc-client-test"), never("oidcc-client-test", other)],
			[entry],
			[{ testModule: "oidcc-client-test", variant: reordered }],
		);
		expect(out.modules.map((m) => m.outcome)).toEqual([
			{ kind: "excused", class: "optional" },
			{ kind: "failed", why: ["it never ran"] },
		]);
	});

	it("fails where it holds an instance alone, or an info alone, whatever that info says", () => {
		const entry = skip("oidcc-client-test");
		const declared = [{ testModule: "oidcc-client-test", variant }];
		const instanceOnly: ModuleRun = {
			testModule: "oidcc-client-test",
			variant,
			instance: "i1",
			log: [],
		};
		const infoOnly = (status: string, result: string): ModuleRun => ({
			testModule: "oidcc-client-test",
			variant,
			info: { status, result },
			log: [],
		});
		for (const run of [
			instanceOnly,
			infoOnly("WAITING", "UNKNOWN"),
			infoOnly("INTERRUPTED", "FAILED"),
			infoOnly("FINISHED", "FAILED"),
			infoOnly("FINISHED", "PASSED"),
		]) {
			expect(judged([run], [entry], declared).modules[0]?.outcome).toEqual({
				kind: "failed",
				why: ["declared not run, but it ran"],
			});
		}
	});

	it("is another test where a variant key changes, is missing or is extra", () => {
		const entry = skip("oidcc-client-test");
		for (const declared of [
			{ client_auth_type: "client_secret_post", response_type: "code" },
			{ client_auth_type: "client_secret_basic" },
			{ ...variant, response_mode: "default" },
		]) {
			const out = judged(
				[never("oidcc-client-test")],
				[entry],
				[{ testModule: "oidcc-client-test", variant: declared }],
			);
			expect(out.modules[0]?.outcome).toEqual({ kind: "failed", why: ["it never ran"] });
			expect(out.strayNotRun).toEqual([{ testModule: "oidcc-client-test", variant: declared }]);
			expect(out.unused).toEqual([entry]);
		}
	});

	it("is excused by no entry of another configuration, a partial variant, or a failures entry alone", () => {
		const declared = [{ testModule: "oidcc-client-test", variant }];
		const otherConfiguration = {
			...skip("oidcc-client-test"),
			"configuration-filename": "op.json",
		};
		const partial = { ...skip("oidcc-client-test"), variant: { response_type: "code" } };
		for (const entry of [otherConfiguration, partial] as Expected[]) {
			const out = judged([never("oidcc-client-test")], [entry], declared);
			expect(out.modules[0]?.outcome).toEqual({
				kind: "failed",
				why: ["declared not run, and no entry excuses it"],
			});
			expect(out.unused).toEqual([entry]);
		}
		const failureEntry = {
			...skip("oidcc-client-test"),
			"current-block": "",
			condition: "Check",
			"expected-result": "failure",
		} as Expected;
		const out = outcomesOf([never("oidcc-client-test")], {
			configuration: "rp.json",
			failures: [failureEntry],
			skips: [],
			notRun: declared,
		});
		expect(out.modules[0]?.outcome).toEqual({
			kind: "failed",
			why: ["declared not run, and no entry excuses it"],
		});
		expect(out.unused).toEqual([failureEntry]);
	});

	it("uses one entry of two written alike, the other named unused", () => {
		const first = skip("oidcc-client-test");
		const second = skip("oidcc-client-test");
		const out = judged(
			[never("oidcc-client-test")],
			[first, second],
			[{ testModule: "oidcc-client-test", variant }],
		);
		expect(out.modules[0]?.outcome).toEqual({ kind: "excused", class: "optional" });
		expect(out.unused).toEqual([second]);
	});

	it("names each declaration no test of the plan answers: a test removed or renamed in the suite", () => {
		const declared = [
			{ testModule: "oidcc-client-test", variant },
			{ testModule: "oidcc-client-test-removed", variant },
		];
		const out = judged(
			[never("oidcc-client-test"), never("oidcc-client-test-added")],
			[skip("oidcc-client-test")],
			declared,
		);
		expect(out.modules.map((m) => [m.testModule, m.outcome])).toEqual([
			["oidcc-client-test", { kind: "excused", class: "optional" }],
			// A test the suite added, neither run nor declared, fails as never run.
			["oidcc-client-test-added", { kind: "failed", why: ["it never ran"] }],
		]);
		expect(out.strayNotRun).toEqual([{ testModule: "oidcc-client-test-removed", variant }]);
	});

	it("judges an OP plan as before, nothing declared", () => {
		const ran: ModuleRun = {
			testModule: "oidcc-server",
			variant,
			instance: "s1",
			info: { status: "FINISHED", result: "PASSED" },
			log: [],
		};
		const runs = [ran, never("oidcc-never")];
		const before = outcomesOf(runs, { configuration: "op.json", failures: [], skips: [] });
		const declaredNone = outcomesOf(runs, {
			configuration: "op.json",
			failures: [],
			skips: [],
			notRun: [],
		});
		expect(declaredNone).toEqual(before);
		expect(before.modules.map((m) => m.outcome)).toEqual([
			{ kind: "passed" },
			{ kind: "failed", why: ["it never ran"] },
		]);
		expect(before.strayNotRun).toEqual([]);
	});
});
