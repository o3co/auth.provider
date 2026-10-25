import { auditStandIn } from "@mod/audit/testing";
import clientAllowanceModule from "@mod/client-allowance/module";
import clientsModule from "@mod/clients/module";
import { clientsConfig } from "@mod/clients/testing";
import http from "@mod/http/module";
import { httpConfig } from "@mod/http/testing";
import { kernelConfig } from "@mod/kernel";
import { quietRuntime, takesUnused } from "@mod/kernel/testing";
import { rateLimitStandIn } from "@mod/rate-limit/testing";
import secretHashModule from "@mod/secret-hash/module";
import { tokensStandIn } from "@mod/tokens/testing";
import { expect, it } from "vitest";
import { grantCaller } from "../src/testing.ts";
import { endpointConfig, endpointModules } from "./deployment.ts";

const runtime = quietRuntime();

it("takes all it names", async () => {
	const input = {
		modules: endpointModules(rateLimitStandIn, auditStandIn().module),
		config: endpointConfig({ issuer: "https://issuer.example" }),
		runtime,
	};
	// Its own entry alone: another module's takes this composition leaves unused are its owner's to check.
	expect((await takesUnused(input))["token-endpoint"]).toBeUndefined();
});

it("takes all it names as the grant caller other packages' tests compose in its place", async () => {
	const input = {
		modules: [
			http,
			clientsModule,
			secretHashModule,
			tokensStandIn(),
			grantCaller,
			clientAllowanceModule,
		],
		config: { ...kernelConfig(), ...httpConfig(), ...clientsConfig([]) },
		runtime,
	};
	// Its own entry alone: another module's takes this composition leaves unused are its owner's to check.
	expect((await takesUnused(input))["token-endpoint"]).toBeUndefined();
});
