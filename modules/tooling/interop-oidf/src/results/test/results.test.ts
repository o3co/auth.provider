import { describe, expect, it } from "vitest";
import type { Expected } from "../../expected/expected.ts";
import { type ModuleRun, outcomesOf } from "../results.ts";

const variant = {
	client_auth_type: "client_secret_basic",
	response_type: "code",
	response_mode: "default",
};
const block = { blockId: "b1", startBlock: true, src: "-START-BLOCK-", msg: "Verify response" };
const failing = (src: string, result = "FAILURE") => ({ blockId: "b1", src, result });

const run = (
	testModule: string,
	result: string,
	log: ModuleRun["log"] = [],
	status = "FINISHED",
): ModuleRun => ({
	testModule,
	variant,
	instance: `${testModule}-1`,
	info: { status, result },
	log,
});

const entry = (fields: Record<string, unknown>): Expected =>
	({
		"test-name": "oidcc-server",
		variant,
		"configuration-filename": "op.json",
		"current-block": "Verify response",
		condition: "CheckX",
		"expected-result": "failure",
		class: "adaptation",
		adaptation: "pkce",
		...fields,
	}) as Expected;

const judged = (runs: ModuleRun[], failures: Expected[] = [], skips: Expected[] = []) =>
	outcomesOf(runs, { configuration: "op.json", failures, skips });

describe("each suite test's outcome, as the harness reports it", () => {
	it("is passed for a finished test with no failure or warning", () => {
		const [o] = judged([
			run("oidcc-server", "PASSED", [block, failing("CheckY", "SUCCESS")]),
		]).modules;
		expect(o?.outcome).toEqual({ kind: "passed" });
	});

	it("is failed for each failure or warning no entry expects, naming its block and condition", () => {
		const [o] = judged([
			run("oidcc-server", "FAILED", [block, failing("CheckX"), failing("CheckW", "WARNING")]),
		]).modules;
		expect(o?.outcome).toEqual({
			kind: "failed",
			why: ["FAILURE Verify response: CheckX", "WARNING Verify response: CheckW"],
		});
	});

	it("is excused by its entries' class where every failure was expected, exactly", () => {
		const runs = [run("oidcc-server", "FAILED", [block, failing("CheckX")])];
		expect(judged(runs, [entry({})]).modules[0]?.outcome).toEqual({
			kind: "excused",
			class: "adaptation",
		});
		// Another block, condition, kind, variant or configuration file is no match.
		for (const other of [
			{ "current-block": "Other" },
			{ condition: "CheckZ" },
			{ "expected-result": "warning" },
			{ variant: { ...variant, response_mode: "form_post" } },
			{ "configuration-filename": "other.json" },
		]) {
			expect(judged(runs, [entry(other)]).modules[0]?.outcome.kind).toBe("failed");
		}
	});

	it("is failed for a skip no entry expects, and excused for one an entry does", () => {
		const runs = [run("oidcc-server", "SKIPPED")];
		expect(judged(runs).modules[0]?.outcome.kind).toBe("failed");
		const skip = entry({
			"current-block": undefined,
			condition: undefined,
			"expected-result": undefined,
			class: "out-of-scope",
			item: "x",
			adaptation: undefined,
		});
		expect(judged(runs, [], [skip]).modules[0]?.outcome).toEqual({
			kind: "excused",
			class: "out-of-scope",
		});
	});

	it("is waiting for a person's review where the suite asks for one, and so never passed", () => {
		expect(judged([run("oidcc-server", "REVIEW", [block])]).modules[0]?.outcome).toEqual({
			kind: "review",
		});
	});

	it("is failed for a test that did not finish, or never ran", () => {
		expect(judged([run("oidcc-server", "UNKNOWN", [], "RUNNING")]).modules[0]?.outcome.kind).toBe(
			"failed",
		);
		const never: ModuleRun = { testModule: "oidcc-server", variant, log: [] };
		expect(judged([never]).modules[0]?.outcome).toEqual({ kind: "failed", why: ["it never ran"] });
	});

	it("names each entry no test used, as the suite's runner would fail it", () => {
		const unused = entry({ condition: "Never" });
		const { unused: found } = judged([run("oidcc-server", "PASSED", [block])], [unused]);
		expect(found).toEqual([unused]);
	});
});
