import { grants } from "@mod/grants";
import { issuer } from "@mod/issuer";
import { contract, defineModule, kernelConfig } from "@mod/kernel";
import { takesUnused } from "@mod/kernel/testing";
import { expect, it } from "vitest";
import clientCredentials from "../src/module.ts";

it("takes the issuer, and nothing it names goes untaken", async () => {
	const collected = contract<unknown>("test.grants");
	const beside = defineModule({ name: "beside", takes: [grants] }, (m) => [
		m.provide(issuer).by(() => ({ url: "https://as.example" }) as never),
		m.provide(collected).by((c) => c.collect(grants)),
	]);
	const input = { modules: [beside, clientCredentials], config: kernelConfig() };
	// Its own entry alone: another module's takes this composition leaves unused are its owner's to check.
	expect((await takesUnused(input))["client-credentials"]).toBeUndefined();
});
