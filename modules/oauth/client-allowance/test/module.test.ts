import { clients } from "@mod/clients";
import clientsModule from "@mod/clients/module";
import { clientsConfig, confidentialClient } from "@mod/clients/testing";
import { assemble, kernelConfig } from "@mod/kernel";
import { takesUnused } from "@mod/kernel/testing";
import secretHashModule from "@mod/secret-hash/module";
import { expect, it } from "vitest";
import { clientAllowance } from "../src/contract.ts";
import clientAllowanceModule from "../src/module.ts";
import { allowancesFor } from "../src/testing.ts";

/** The module beside clients, with one registered client holding these sections. */
const assembly = (sections: Readonly<Record<string, unknown>>) => ({
	modules: [clientsModule, secretHashModule, clientAllowanceModule],
	config: { ...kernelConfig(), ...clientsConfig([confidentialClient({ id: "c", sections })]) },
});
const boot = (sections: Readonly<Record<string, unknown>>) => assemble(assembly(sections));

it("decides over a registered client's section, written under the module's name", async () => {
	const app = await boot(
		allowancesFor({ grants: ["client_credentials"], audiences: ["https://api"] }),
	);
	const client = await app.get(clients).find("c");
	if (!client) throw new Error("no client");
	expect(clientAllowance.allowsGrant(client, "client_credentials")).toBe(true);
	expect(clientAllowance.allowsGrant(client, "refresh_token")).toBe(false);
	expect(clientAllowance.allowsAudience(client, "https://api", "https://as")).toBe(true);
});

it("allows nothing to a client without the section", async () => {
	const client = await (await boot({})).get(clients).find("c");
	if (!client) throw new Error("no client");
	expect(clientAllowance.allowsGrant(client, "client_credentials")).toBe(false);
	expect(clientAllowance.allowedIssuance(client, "read", "https://as").kind).toBe("error");
});

it("refuses boot for a field the section does not name", async () => {
	await expect(boot(allowancesFor({ grant: ["x"] } as never))).rejects.toMatchObject({
		name: "BootRefused",
	});
});

it("refuses boot for offline_access among the scopes or the default scopes, naming the entry", async () => {
	const refused = (allowed: Parameters<typeof allowancesFor>[0]) =>
		boot(allowancesFor(allowed)).then(
			() => [],
			(error: { refusals: readonly { where: string; reason: string }[] }) => error.refusals,
		);
	const reason = "offline_access allows nothing: offline access is not offered, so remove it";
	expect(await refused({ scopes: ["openid", "offline_access"] })).toEqual([
		{ where: "clients.registered.0.sections.client-allowance.scopes.1", reason },
	]);
	expect(await refused({ scopes: ["openid"], "default-scopes": ["offline_access"] })).toEqual([
		{ where: "clients.registered.0.sections.client-allowance.default-scopes.0", reason },
	]);
});

it("takes nothing: its one contribution is a value", async () => {
	// Its own entry alone: another module's takes this composition leaves unused are its owner's to check.
	expect((await takesUnused(assembly({})))["client-allowance"]).toBeUndefined();
});
