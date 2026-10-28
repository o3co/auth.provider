import { originEvidence } from "@mod/csrf";
import { grants, sessionIssuances } from "@mod/grants";
import { issuer } from "@mod/issuer";
import { contract, defineModule, kernelConfig } from "@mod/kernel";
import { takesUnused } from "@mod/kernel/testing";
import { sessions } from "@mod/session";
import { tokens } from "@mod/tokens";
import { expect, it } from "vitest";
import sessionGrant from "../src/module.ts";

it("takes all its module names", async () => {
	const collected = contract<unknown>("test.grants");
	const beside = defineModule({ name: "beside", replicaSafe: true, takes: [grants] }, (m) => [
		m.provide(originEvidence).by(() => ({}) as never),
		m.provide(sessions).by(() => ({}) as never),
		m.provide(tokens).by(() => ({}) as never),
		m.provide(issuer).by(() => ({ url: "https://as.example" }) as never),
		m.contribute(sessionIssuances).by(() => ({ issued: async () => {} })),
		m.provide(collected).by((c) => c.collect(grants)),
	]);
	const input = { modules: [beside, sessionGrant], config: kernelConfig() };
	// Its own entry alone: another module's takes this composition leaves unused are its owner's to check.
	expect((await takesUnused(input))["session-grant"]).toBeUndefined();
});
