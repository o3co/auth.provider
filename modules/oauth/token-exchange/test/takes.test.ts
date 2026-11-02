import clientAllowanceModule from "@mod/client-allowance/module";
import clientsModule from "@mod/clients/module";
import { clientsConfig } from "@mod/clients/testing";
import http from "@mod/http/module";
import { httpConfig } from "@mod/http/testing";
import issuerModule from "@mod/issuer/module";
import { issuerConfig } from "@mod/issuer/testing";
import { kernelConfig } from "@mod/kernel";
import { quietRuntime, takesUnused } from "@mod/kernel/testing";
import secretHashModule from "@mod/secret-hash/module";
import { grantCaller } from "@mod/token-endpoint/testing";
import { tokensStandIn } from "@mod/tokens/testing";
import { expect, it } from "vitest";
import tokenExchange from "../src/module.ts";

it("takes all it names, with a longest lifetime written or not", async () => {
	for (const settings of [{}, { "max-lifetime": "1h" }]) {
		const input = {
			modules: [
				http,
				tokensStandIn(),
				issuerModule,
				clientsModule,
				secretHashModule,
				grantCaller,
				clientAllowanceModule,
				tokenExchange,
			],
			config: {
				...kernelConfig(),
				...httpConfig(),
				...issuerConfig(),
				...clientsConfig([]),
				"token-exchange": settings,
			},
			runtime: quietRuntime(),
		};
		// Its own entry alone: another module's takes this composition leaves unused are its owner's to check.
		expect((await takesUnused(input))["token-exchange"], JSON.stringify(settings)).toBeUndefined();
	}
});
