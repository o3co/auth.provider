import { auditStandIn } from "@mod/audit/testing";
import clientAllowanceModule from "@mod/client-allowance/module";
import { authMethods } from "@mod/clients";
import clientsModule from "@mod/clients/module";
import http from "@mod/http/module";
import { httpConfig } from "@mod/http/testing";
import { type MetadataItem, metadata } from "@mod/issuer";
import issuerModule from "@mod/issuer/module";
import { issuerConfig } from "@mod/issuer/testing";
import { assemble, contract, defineModule, kernelConfig, type Module } from "@mod/kernel";
import { quietRuntime, takesUnused } from "@mod/kernel/testing";
import { rateLimitStandIn } from "@mod/rate-limit/testing";
import secretHashModule from "@mod/secret-hash/module";
import { grantCaller } from "@mod/token-endpoint/testing";
import { tokensStandIn } from "@mod/tokens/testing";
import { expect, it } from "vitest";
import { revocableKinds } from "../src/contract.ts";
import tokenControl from "../src/module.ts";

const runtime = quietRuntime();

const refreshKind = defineModule({ name: "refresh-kind", takes: [] }, (m) => [
	m.contribute(revocableKinds).by(() => ({ hint: "refresh_token", revoke: async () => "unknown" })),
]);

const published = contract<readonly MetadataItem[]>("published");
const reader = defineModule({ name: "reader", takes: [metadata] }, (m) => [
	m.provide(published).by((c) => c.collect(metadata)),
]);

/** What `documentOf` assembles: tokens revocable or not, the public origin if one is written. */
const assembly = (revocable: boolean, origin?: string, extra: Module[] = []) => ({
	modules: [
		http,
		tokensStandIn({ revocable }),
		issuerModule,
		clientsModule,
		secretHashModule,
		grantCaller,
		clientAllowanceModule,
		tokenControl,
		rateLimitStandIn,
		auditStandIn().module,
		reader,
		...extra,
	],
	config: {
		...kernelConfig(),
		...httpConfig(origin ? { "public-origin": origin } : {}),
		...issuerConfig({ url: origin ?? "https://issuer.example" }),
	},
	runtime,
});

/** The metadata items with a value of a deployment reached at `origin` if one is written. */
async function documentOf(revocable: boolean, origin?: string, extra: Module[] = []) {
	const app = await assemble(assembly(revocable, origin, extra));
	const items = app.get(published).filter((item) => item.value !== undefined);
	return Object.fromEntries(items.map((item) => [item.name, item.value]));
}

it("publishes where it introspects and revokes, on the public origin", async () => {
	const document = await documentOf(true, "https://as.example");
	expect(document.introspection_endpoint).toBe("https://as.example/oauth/introspect");
	expect(document.revocation_endpoint).toBe("https://as.example/oauth/revoke");
});

it("publishes revocation only where some token can be revoked, and both on the issuer's origin where no public origin is written", async () => {
	expect(await documentOf(false, "https://as.example")).not.toHaveProperty("revocation_endpoint");
	expect((await documentOf(false, "https://as.example", [refreshKind])).revocation_endpoint).toBe(
		"https://as.example/oauth/revoke",
	);
	const unplaced = await documentOf(true);
	expect(unplaced.introspection_endpoint).toBe("https://issuer.example/oauth/introspect");
	expect(unplaced.revocation_endpoint).toBe("https://issuer.example/oauth/revoke");
});

/** A signed method, as client-assertion contributes one. */
const signed = defineModule({ name: "signed-method", takes: [] }, (m) => [
	m.contribute(authMethods).by(() => ({
		name: "private_key_jwt",
		signingAlgorithms: ["ES256"],
		claimed: () => undefined,
		verify: async () => false,
	})),
]);

it("publishes how a client authenticates at each: no public client at introspection, and the algorithms of signed methods [rfc8414-2-l] [rfc8414-2-n]", async () => {
	const plain = await documentOf(true, "https://as.example");
	expect(plain.introspection_endpoint_auth_methods_supported).toEqual([
		"client_secret_basic",
		"client_secret_post",
	]);
	expect(plain.revocation_endpoint_auth_methods_supported).toEqual([
		"client_secret_basic",
		"client_secret_post",
		"none",
	]);
	expect(plain).not.toHaveProperty("introspection_endpoint_auth_signing_alg_values_supported");
	expect(plain).not.toHaveProperty("revocation_endpoint_auth_signing_alg_values_supported");
	const withSigned = await documentOf(true, "https://as.example", [signed]);
	expect(withSigned.introspection_endpoint_auth_methods_supported).toContain("private_key_jwt");
	expect(withSigned.introspection_endpoint_auth_signing_alg_values_supported).toEqual(["ES256"]);
	expect(withSigned.revocation_endpoint_auth_signing_alg_values_supported).toEqual(["ES256"]);
	// Where revocation is not published, neither is how to authenticate there.
	const unrevocable = await documentOf(false, "https://as.example", [signed]);
	expect(unrevocable).not.toHaveProperty("revocation_endpoint_auth_methods_supported");
	expect(unrevocable).not.toHaveProperty("revocation_endpoint_auth_signing_alg_values_supported");
});

it("takes all its module names, tokens revocable or not, a kind contributed or not, with an origin or none", async () => {
	for (const revocable of [true, false])
		for (const extra of [[], [refreshKind]])
			for (const origin of ["https://as.example", undefined]) {
				const input = assembly(revocable, origin, extra);
				// Its own entry alone: another module's takes this composition leaves unused are its owner's to check.
				expect(
					(await takesUnused(input))["token-control"],
					`${revocable} ${extra.length} ${origin}`,
				).toBeUndefined();
			}
});
