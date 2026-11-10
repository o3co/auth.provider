import { auditStandIn } from "@mod/audit/testing";
import clientAllowanceModule from "@mod/client-allowance/module";
import { allowancesFor } from "@mod/client-allowance/testing";
import clientCredentialsModule from "@mod/client-credentials/module";
import { clientsConfig, confidentialClient } from "@mod/clients/testing";
import { type MetadataItem, metadata } from "@mod/issuer";
import { assemble, BootRefused, contract, defineModule, type Module } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { rateLimitStandIn } from "@mod/rate-limit/testing";
import { expect, it } from "vitest";
import tokenEndpoint from "../src/module.ts";
import { endpointConfig, endpointModules } from "./deployment.ts";

const quiet = quietRuntime({
	clock: { now: () => 1_800_000_000_000 },
	random: { bytes: (n) => new Uint8Array(n).fill(1) },
});
const published = contract<readonly MetadataItem[]>("published");
const reader = defineModule({ name: "reader", replicaSafe: true, takes: [metadata] }, (m) => [
	m.provide(published).by((c) => c.collect(metadata)),
]);

/** A deployment of the endpoint and `modules`, registering a client allowed each list of `grants`. */
const boot = (modules: Module[], ...grants: string[][]) =>
	assemble({
		// The endpoint as the helper composes it, but for client-credentials, which `modules` may add.
		modules: [
			...endpointModules(
				rateLimitStandIn,
				auditStandIn().module,
				clientAllowanceModule,
				reader,
			).filter((module) => module !== clientCredentialsModule),
			...modules,
		],
		config: {
			...endpointConfig(),
			...clientsConfig(
				grants.map((allowed, i) =>
					confidentialClient({ id: `c${i}`, sections: allowancesFor({ grants: allowed }) }),
				),
			),
		},
		runtime: quiet,
	});
/** The boot's refusals, none where it boots; any other error is thrown, so it never reads as a boot. */
const refusals = (deployment: Promise<unknown>) =>
	deployment.then(
		() => [],
		(error) => {
			if (!BootRefused.is(error)) throw error;
			return error.refusals.map((r) => `${r.where}: ${r.reason}`);
		},
	);

it("publishes as grant_types_supported only the grants composed, client_credentials only with client-credentials", async () => {
	const supported = async (modules: Module[]) =>
		(await boot(modules)).get(published).find((item) => item.name === "grant_types_supported")
			?.value;
	expect(await supported([clientCredentialsModule])).toEqual(["client_credentials"]);
	expect(tokenEndpoint.name).toBe("token-endpoint");
});

it("refuses to boot with no grant composed, so grant_types_supported is never empty", async () => {
	expect(await refusals(boot([]))).toEqual([
		"token-endpoint: no grant is composed: compose one, or leave the token endpoint out",
	]);
	expect(await refusals(boot([clientCredentialsModule]))).toEqual([]);
});
