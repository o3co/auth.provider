import { auditStandIn } from "@mod/audit/testing";
import clientAllowanceModule from "@mod/client-allowance/module";
import { allowancesFor } from "@mod/client-allowance/testing";
import clientCredentialsModule from "@mod/client-credentials/module";
import { clientsConfig, confidentialClient } from "@mod/clients/testing";
import { type MetadataItem, metadata } from "@mod/issuer";
import { assemble, BootRefused, contract, defineModule, type Module } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { rateLimitStandIn } from "@mod/rate-limit/testing";
import { describe, expect, it } from "vitest";
import tokenEndpoint from "../src/module.ts";
import { endpointConfig, endpointModules } from "./deployment.ts";

const quiet = quietRuntime({
	clock: { now: () => 1_800_000_000_000 },
	random: { bytes: (n) => new Uint8Array(n).fill(1) },
});
const published = contract<readonly MetadataItem[]>("published");
const reader = defineModule({ name: "reader" }, (m) => [
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

describe("a registered client allowed a grant nothing composed serves", () => {
	it("refuses boot at the grant's place in the client's list, naming the module that serves it", async () => {
		expect(
			await refusals(boot([], ["authorization_code"], [], ["refresh_token", "urn:x:own"])),
		).toEqual([
			"clients.registered.0.sections.client-allowance.grants.0: no composed module serves this grant: compose code-grant, or take it out of the client's grants",
			"clients.registered.2.sections.client-allowance.grants.0: no composed module serves this grant: compose refresh, or take it out of the client's grants",
			"clients.registered.2.sections.client-allowance.grants.1: no composed module serves this grant: compose the module that serves it, or take it out of the client's grants",
		]);
	});

	it("names client-credentials for client_credentials, which token-endpoint no longer serves itself", async () => {
		expect(await refusals(boot([], ["client_credentials"]))).toEqual([
			"clients.registered.0.sections.client-allowance.grants.0: no composed module serves this grant: compose client-credentials, or take it out of the client's grants",
		]);
		expect(await refusals(boot([clientCredentialsModule], ["client_credentials"]))).toEqual([]);
	});

	it("names no module for a type that is a name every object has", async () => {
		const unknown = "no composed module serves this grant: compose the module that serves it";
		expect(
			await refusals(boot([], ["constructor", "__proto__", "toString", "hasOwnProperty"])),
		).toEqual(
			[0, 1, 2, 3].map(
				(j) =>
					`clients.registered.0.sections.client-allowance.grants.${j}: ${unknown}, or take it out of the client's grants`,
			),
		);
	});

	it("never names the client's id or the grant type itself", async () => {
		const told = (await refusals(boot([], ["urn:x:secret-name"]))).join();
		expect(told).not.toMatch(/c0|urn:x:secret-name/);
	});
});

it("publishes as grant_types_supported only the grants composed, client_credentials only with client-credentials", async () => {
	const supported = async (modules: Module[]) =>
		(await boot(modules)).get(published).find((item) => item.name === "grant_types_supported")
			?.value;
	expect(await supported([])).toEqual([]);
	expect(await supported([clientCredentialsModule])).toEqual(["client_credentials"]);
	expect(tokenEndpoint.name).toBe("token-endpoint");
});
