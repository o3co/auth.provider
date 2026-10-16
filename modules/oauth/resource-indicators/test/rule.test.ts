import { type TargetRule, targetRules } from "@mod/grants";
import { assemble, contract, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { beforeAll, describe, expect, it } from "vitest";
import resourceIndicators from "../src/module.ts";

/** The rules composed, as token-endpoint collects them. */
const composed = contract<readonly TargetRule[]>("test.composed-rules");
const probe = defineModule({ name: "probe" }, (m) => [
	m.provide(composed).by((c) => c.collect(targetRules)),
]);
let rule: TargetRule;
beforeAll(async () => {
	const app = await assemble({
		modules: [probe, resourceIndicators],
		// Many instances: the rule keeps nothing, so the module never refuses them.
		config: kernelConfig({ deployment: "multi" }),
		runtime: quietRuntime(),
	});
	const [only, ...more] = app.get(composed);
	if (!only || more.length > 0) throw new Error("one rule expected");
	rule = only;
});
const audience = ["https://a.example"];
const allowed = new Set(["https://a.example", "https://b.example"]);
/** The rule's verdict for these parameters, within the allowed audiences. */
const verdictFor = (params: Record<string, string>) =>
	rule.target({ param: (name) => params[name], audience, within: (a) => allowed.has(a) });
const refused = {
	kind: "error",
	error: "invalid_target",
	description: "resource is not an audience this client may be issued",
};

describe("resource-indicators", () => {
	it("keeps the default audience when no resource, or an empty one, is asked", () => {
		expect(verdictFor({})).toEqual({ kind: "audience", audience });
		expect(verdictFor({ resource: "" })).toEqual({ kind: "audience", audience });
	});

	it("narrows to the resource asked when the issuance may have it", () => {
		expect(verdictFor({ resource: "https://b.example" })).toEqual({
			kind: "audience",
			audience: ["https://b.example"],
		});
	});

	it("refuses a resource the issuance may not have, telling a fixed text rather than the value", () => {
		expect(verdictFor({ resource: "https://c.example" })).toEqual(refused);
	});

	it("refuses a resource sent to a grant that takes no audience, with a fixed text, and asks nothing of one left out or empty", () => {
		const untargeted = (params: Record<string, string>) =>
			rule.untargeted?.({ param: (name) => params[name] });
		expect(untargeted({ resource: "https://b.example" })).toEqual({
			kind: "error",
			error: "invalid_target",
			description: "this grant takes no resource",
		});
		expect(untargeted({})).toBeUndefined();
		expect(untargeted({ resource: "" })).toBeUndefined();
	});

	it("refuses resource sent more than once, as only one audience is ever issued, and leaves any other name alone", () => {
		expect(rule.repeated?.("resource")).toEqual({
			kind: "error",
			error: "invalid_target",
			description: "one resource at most",
		});
		expect(rule.repeated?.("scope")).toBeUndefined();
	});

	it("compares the resource as a string, never as a URI it would normalize", () => {
		for (const resource of ["HTTPS://B.EXAMPLE", "https://b.example/", "https://b.example\t"]) {
			expect(verdictFor({ resource }), JSON.stringify(resource)).toEqual(refused);
		}
	});
});
