import { type TargetRule, targetRules } from "@mod/grants";
import { assemble, contract, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime, takesUnused } from "@mod/kernel/testing";
import { beforeAll, describe, expect, it } from "vitest";
import resourceIndicators from "../src/module.ts";

/** The rules composed, as token-endpoint collects them. */
const composed = contract<readonly TargetRule[]>("test.composed-rules");
const probe = defineModule({ name: "probe", replicaSafe: true, takes: [targetRules] }, (m) => [
	m.provide(composed).by((c) => c.collect(targetRules)),
]);
let rule: TargetRule;
const input = {
	modules: [probe, resourceIndicators],
	// Many instances: the rule keeps nothing, so the module never refuses them.
	config: kernelConfig({ deployment: "multi" }),
	runtime: quietRuntime(),
};
beforeAll(async () => {
	const app = await assemble(input);
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
	it("keeps the default audience when no resource, or an empty one, is asked [rfc6749-3.2-b]", () => {
		expect(verdictFor({})).toEqual({ kind: "audience", audience });
		expect(verdictFor({ resource: "" })).toEqual({ kind: "audience", audience });
	});

	it("narrows to the resource asked when the issuance may have it", () => {
		expect(verdictFor({ resource: "https://b.example" })).toEqual({
			kind: "audience",
			audience: ["https://b.example"],
		});
	});

	it("refuses a resource that is not an absolute URI, or carries a fragment, whatever audience is registered [rfc8707-2-a] [rfc8707-2-b]", () => {
		// Every value here is registered: the form is refused before any audience is compared.
		const anywhere = (resource: string) =>
			rule.target({
				param: (name) => (name === "resource" ? resource : undefined),
				audience,
				within: () => true,
			});
		for (const resource of ["a.example", "/api", "api", "https://a.example/ x"]) {
			expect(anywhere(resource), resource).toEqual({
				kind: "error",
				error: "invalid_target",
				description: "resource is not an absolute URI",
			});
		}
		for (const resource of ["https://a.example/#x", "urn:example:a#"]) {
			expect(anywhere(resource), resource).toEqual({
				kind: "error",
				error: "invalid_target",
				description: "resource carries a fragment",
			});
		}
		expect(anywhere("urn:example:api")).toEqual({
			kind: "audience",
			audience: ["urn:example:api"],
		});
	});

	it("refuses a resource the issuance may not have, telling a fixed text rather than the value", () => {
		expect(verdictFor({ resource: "https://c.example" })).toEqual(refused);
	});

	it("refuses a resource sent to a grant that takes no audience, with a fixed text, and asks nothing of one left out or empty [rfc6749-3.2-b]", () => {
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
		for (const resource of ["HTTPS://B.EXAMPLE", "https://b.example/"]) {
			expect(verdictFor({ resource }), JSON.stringify(resource)).toEqual(refused);
		}
		// A tab URL parsing would strip is no URI as written, refused before any comparison.
		expect(verdictFor({ resource: "https://b.example\t" })).toEqual({
			...refused,
			description: "resource is not an absolute URI",
		});
	});
});

it("takes nothing, as it declares", async () => {
	// Its own entry alone: another module's takes this composition leaves unused are its owner's to check.
	expect((await takesUnused(input))["resource-indicators"]).toBeUndefined();
});
