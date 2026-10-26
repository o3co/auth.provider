import { describe, expect, it } from "vitest";
import { conditionOf, evaluate, inputOf, type RunContext } from "../expression.ts";

const release: RunContext = { event_name: "push", ref: "refs/heads/release/0.19.1", base_ref: "" };
const develop: RunContext = { event_name: "push", ref: "refs/heads/develop", base_ref: "" };
const evidence =
	"(github.event_name == 'push' && startsWith(github.ref, 'refs/heads/release/')) || (github.event_name == 'pull_request' && github.base_ref == 'main')";

describe("evaluate", () => {
	it("reads the run's github context, comparing strings without regard to case", () => {
		expect(evaluate(evidence, release)).toBe(true);
		expect(evaluate(evidence, develop)).toBe(false);
		expect(evaluate("github.event_name == 'PUSH'", release)).toBe(true);
		expect(evaluate("startsWith(github.ref, 'REFS/HEADS/')", release)).toBe(true);
	});

	it("binds ! tighter than ==, as GitHub does", () => {
		expect(evaluate("!github.ref == false", release)).toBe(true);
	});

	it("gives && and || their operands, so `cond && '' || x` is x whatever cond is", () => {
		expect(evaluate(`(${evidence}) && '' || 'maven'`, release)).toBe("maven");
		expect(evaluate(`!(${evidence}) && 'maven' || ''`, release)).toBe("");
		expect(evaluate(`!(${evidence}) && 'maven' || ''`, develop)).toBe("maven");
	});

	it("leaves undecided what the github context does not decide, short of a decided side", () => {
		for (const source of [
			"matrix.node == '24'",
			"needs.plan.result == 'success'",
			"success()",
			"env.X",
			"fromJSON('1')",
		]) {
			expect(evaluate(source, release)).toHaveProperty("unknown");
		}
		expect(evaluate("false && matrix.node", release)).toBe(false);
		expect(evaluate("true || needs.plan.result", release)).toBe(true);
		expect(evaluate("!cancelled() && needs.plan.result == 'success'", release)).toHaveProperty(
			"unknown",
		);
	});

	it("leaves undecided what it cannot read", () => {
		expect(evaluate("github.ref == 'x", release)).toHaveProperty("unknown");
		expect(evaluate("github.ref > 'x'", release)).toHaveProperty("unknown");
		expect(evaluate("github.ref 'x'", release)).toHaveProperty("unknown");
	});
});

describe("inputOf and conditionOf", () => {
	it("reads a plain value as itself, an expression alone by evaluating it, and mixed text as undecided", () => {
		expect(inputOf(false, release)).toBe(false);
		expect(inputOf("maven", release)).toBe("maven");
		expect(inputOf("${{ github.event_name }}", release)).toBe("push");
		expect(inputOf("on ${{ github.ref }}", release)).toHaveProperty("unknown");
		expect(inputOf("${{ true }}-${{ false }}", release)).toHaveProperty("unknown");
	});

	it("reads an if written with or without ${{ }}", () => {
		expect(conditionOf("github.event_name == 'push'", release)).toBe(true);
		expect(conditionOf("${{ github.event_name == 'schedule' }}", release)).toBe(false);
	});
});
