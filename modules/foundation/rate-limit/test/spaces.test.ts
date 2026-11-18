import { auditStandIn } from "@mod/audit/testing";
import { assemble, contract, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { type Space, spaces } from "@mod/store";
import { simulatedStore } from "@mod/store/testing";
import { expect, it } from "vitest";
import rateLimitModule from "../src/module.ts";

const declared = contract<readonly Space[]>("rate-limit-test.spaces");
const reader = defineModule({ name: "reader", replicaSafe: true, takes: [spaces] }, (m) => [
	m.provide(declared).by(async (c) => c.collect(spaces)),
]);

it("declares both window spaces pseudonymous, with neither an eraser nor a bound yet", async () => {
	const app = await assemble({
		modules: [rateLimitModule, simulatedStore().module, auditStandIn().module, reader],
		config: kernelConfig(),
		runtime: quietRuntime(),
	});
	const named = Object.fromEntries(app.get(declared).map((s) => [s.name, s]));
	for (const name of ["rate-limit.windows", "rate-limit.attempts"]) {
		expect(named[name]?.subjectData, name).toBe("pseudonymous");
		expect([named[name]?.erasedBy, named[name]?.boundedMs], name).toEqual([undefined, undefined]);
	}
});
