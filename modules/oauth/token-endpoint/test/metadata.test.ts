import { auditStandIn } from "@mod/audit/testing";
import { authMethods } from "@mod/clients";
import { composedGrants, grants } from "@mod/grants";
import { type MetadataItem, metadata } from "@mod/issuer";
import { assemble, contract, defineModule, type Module } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { rateLimitStandIn } from "@mod/rate-limit/testing";
import { expect, it } from "vitest";
import { endpointConfig, endpointModules } from "./deployment.ts";

const quiet = quietRuntime({
	clock: { now: () => 1_800_000_000_000 },
	random: { bytes: (n) => new Uint8Array(n).fill(1) },
});

const echo = defineModule({ name: "echo-grant", replicaSafe: true, takes: [] }, (m) => [
	m.contribute(grants).by(() => ({
		grantType: "urn:test:echo",
		readsAmbient: "none",
		handle: async () => ({ kind: "issued", body: {} }),
	})),
]);
const signed = defineModule({ name: "signed-method", replicaSafe: true, takes: [] }, (m) => [
	m.contribute(authMethods).by(() => ({
		name: "test_jwt",
		// An assertion method, as private_key_jwt and client_secret_jwt are: clients refuses one naming no algorithm.
		assertion: true,
		signingAlgorithms: ["ES256"],
		claimed: () => undefined,
		verify: async () => false,
	})),
]);

const published = contract<readonly MetadataItem[]>("published");
const reader = defineModule({ name: "reader", replicaSafe: true, takes: [metadata] }, (m) => [
	m.provide(published).by((c) => c.collect(metadata)),
]);

/** A deployment with these modules, reached at `origin` if one is written. */
async function appOf(extra: Module[], origin?: string) {
	return assemble({
		modules: endpointModules(rateLimitStandIn, auditStandIn().module, reader, ...extra),
		config: {
			...endpointConfig({
				peer: origin ? { "public-origin": origin } : {},
				issuer: `${origin ?? "https://issuer.example"}/tenant`,
			}),
		},
		runtime: quiet,
	});
}

/** The metadata items with a value of a deployment with these modules, reached at `origin` if one is written. */
async function documentOf(extra: Module[], origin?: string) {
	const app = await appOf(extra, origin);
	const items = app.get(published).filter((item) => item.value !== undefined);
	return Object.fromEntries(items.map((item) => [item.name, item.value]));
}

it("publishes its location, with no fragment, the grants it dispatches to, and the client authentication methods, an assertion method's beside its algorithms [rfc8414-2-h] [rfc6749-3.2-a]", async () => {
	const document = await documentOf([echo, signed], "https://as.example");
	expect(document.token_endpoint).toBe("https://as.example/oauth/token");
	expect(new URL(String(document.token_endpoint)).hash).toBe("");
	expect(document.grant_types_supported).toEqual(["client_credentials", "urn:test:echo"]);
	expect(document.token_endpoint_auth_methods_supported).toEqual([
		"client_secret_basic",
		"client_secret_post",
		"none",
		"test_jwt",
	]);
	expect(document.token_endpoint_auth_signing_alg_values_supported).toEqual(["ES256"]);
});

it("lists no grant that is not contributed, the password grant never, and no algorithms when no method signs [rfc9700-2.4-a]", async () => {
	const document = await documentOf([]);
	expect(document.grant_types_supported).toEqual(["client_credentials"]);
	expect(document.grant_types_supported).not.toContain("password");
	expect(document).not.toHaveProperty("token_endpoint_auth_signing_alg_values_supported");
});

it("publishes its location on the issuer's origin where no public origin is written [rfc8414-2-c] [oidc-discovery-3-f]", async () => {
	const document = await documentOf([]);
	expect(document.token_endpoint).toBe("https://issuer.example/oauth/token");
});

it("says which grant types are composed: the built-in one and those contributed, no other", async () => {
	const composed = (await appOf([echo])).get(composedGrants);
	expect([...composed]).toEqual(["client_credentials", "urn:test:echo"]);
	expect(composed.has("authorization_code")).toBe(false);
});
