import { audit } from "@mod/audit";
import { assemble, defineModule, kernelConfig } from "@mod/kernel";
import { factors } from "@mod/mfa";
import { flowParts } from "@mod/mfa-flows";
import { lockouts } from "@mod/rate-limit";
import { revocations } from "@mod/subject-revocation";
import { expect, it } from "vitest";
import { mfaReset } from "../src/contract.ts";
import resetModule from "../src/module.ts";

it("resets over the contracts it is given, releasing mfa-flows' lockout by its name and policy", async () => {
	const released: unknown[] = [];
	const policy = { budget: 10 };
	const parts = defineModule({ name: "parts" }, (m) => [
		m.provide(flowParts).by(() => ({ lockout: { name: "mfa", policy } }) as never),
		m.provide(factors).by(() => ({ clear: async () => ({ count: 1, kinds: ["code"] }) }) as never),
		m.provide(revocations).by(() => ({ record: async () => ({ complete: true }) }) as never),
		m.provide(lockouts).by(
			() =>
				({
					releaseUnder: async (name: string, _key: string, given: unknown) => {
						released.push([name, given === policy]);
						return {};
					},
				}) as never,
		),
		m.provide(audit).by(() => ({ record: () => {}, lost: () => ({}) })),
	]);
	const app = await assemble({ modules: [parts, resetModule], config: kernelConfig() });
	expect(await app.get(mfaReset).reset("ann")).toBe(1);
	expect(released).toEqual([["mfa", true]]);
});
