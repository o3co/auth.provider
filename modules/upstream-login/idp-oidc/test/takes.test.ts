import externalJwtModule from "@mod/external-jwt/module";
import { defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime, takesUnused } from "@mod/kernel/testing";
import { outbound } from "@mod/outbound";
import { outboundRefusals } from "@mod/outbound-policy";
import { expect, it } from "vitest";
import idpModule from "../src/module.ts";

/** Outbound and its refusals, never asked: the type is only built. */
const stubs = defineModule({ name: "outbound", takes: [] }, (m) => [
	m.provide(outbound).by(() => ({}) as never),
	m.provide(outboundRefusals).by(() => ({ explained: () => undefined }) as never),
]);

it("takes all it names", async () => {
	const input = {
		modules: [stubs, externalJwtModule, idpModule],
		config: kernelConfig(),
		runtime: quietRuntime(),
	};
	// Its own entry alone: another module's takes this composition leaves unused are its owner's to check.
	expect((await takesUnused(input))["idp-oidc"]).toBeUndefined();
});
