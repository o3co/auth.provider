import { audit } from "@mod/audit";
import { originEvidence } from "@mod/csrf";
import { site } from "@mod/http";
import { defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime, takesUnused } from "@mod/kernel/testing";
import { sessions } from "@mod/session";
import { handoff } from "@mod/upstream-handoff";
import { users } from "@mod/users";
import { expect, it } from "vitest";
import linkModule from "../src/module.ts";

/** What the link is built over, never asked: the continuation is only built. */
const stubs = defineModule({ name: "stubs", replicaSafe: true, takes: [] }, (m) => [
	m.provide(site).by(() => ({ origin: "https://as.example", secureCookies: true }) as never),
	m.provide(originEvidence).by(() => ({ sameOrigin: () => true })),
	m.provide(sessions).by(() => ({}) as never),
	m.provide(users).by(() => ({}) as never),
	m.provide(audit).by(() => ({ record: () => {}, lost: () => ({}) })),
	m.provide(handoff).by(() => ({}) as never),
]);

it("takes all it names", async () => {
	const input = { modules: [stubs, linkModule], config: kernelConfig(), runtime: quietRuntime() };
	// Its own entry alone: another module's takes this composition leaves unused are its owner's to check.
	expect((await takesUnused(input))["federation-link"]).toBeUndefined();
});
