/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { createApp, defineModule } from "@o3co/auth-provider-core";
import { makeValidCoreConfig } from "@o3co/auth-provider-core/testing";
import type { FederationProvider, FederationRedirectPolicy } from "@o3co/auth-provider-session";
import { describe, expect, it } from "vitest";
import { oidcFederationModule } from "#/module.mjs";
import type { OidcProviderConfig } from "#/oidc.mjs";
import { createFakeIdp } from "./helpers.mjs";

const minBoot = {
	config: makeValidCoreConfig(),
	pathResolver: (p: string) => p,
} as never;

const configFor = (
	idp: Awaited<ReturnType<typeof createFakeIdp>>,
	name: string,
): OidcProviderConfig => ({
	issuer: idp.issuer,
	clientId: idp.clientId,
	clientSecret: "a-client-secret",
	callbackURL: `https://auth.test/session/oauth/federation/${name}/callback`,
	fetch: idp.fetch,
});

// Activator: requires both synthetic resolvers so the boot planner
// materialises the projections into `handle.components`.
const activatorModule = defineModule({
	name: "test-oidc-activator",
	requires: ["federationProviders", "federationRedirectPolicyResolver"] as never,
	contributes: {
		routes: [
			{
				mountPath: "/__test_oidc_noop__",
				id: "test-oidc-noop",
				handler: ((_req: unknown, _res: unknown, next: () => void) => next()) as never,
			},
		],
	},
});

describe("oidcFederationModule boot integration (#524)", () => {
	it("boots two instances against two issuers, each under its own name", async () => {
		const idpA = await createFakeIdp({ issuer: "https://idp-a.test", clientId: "client-a" });
		const idpB = await createFakeIdp({
			issuer: "https://idp-b.test/tenant/b",
			clientId: "client-b",
		});
		const configs = defineModule({
			name: "test-oidc-configs",
			provides: {
				oidcFederationConfigs: () => ({
					"idp-a": configFor(idpA, "idp-a"),
					"idp-b": configFor(idpB, "idp-b"),
				}),
			},
		});

		const handle = await createApp({
			modules: [
				oidcFederationModule("idp-a"),
				oidcFederationModule("idp-b"),
				configs,
				activatorModule,
			],
			bootstrapComponents: minBoot,
		});

		const providers = (handle.components as Record<string, unknown>).federationProviders as
			| ReadonlyMap<string, FederationProvider>
			| undefined;
		expect([...(providers?.keys() ?? [])].sort()).toEqual(["idp-a", "idp-b"]);
		expect(providers?.get("idp-a")?.name).toBe("idp-a");
		expect(providers?.get("idp-b")?.name).toBe("idp-b");

		// Discovery happened once per instance, at boot.
		expect(idpA.requestsTo("/.well-known/openid-configuration")).toHaveLength(1);
		expect(idpB.requestsTo("/.well-known/openid-configuration")).toHaveLength(1);

		// Each instance sends the browser to its own issuer with its own client.
		const urlA = providers?.get("idp-a")?.buildAuthorizationUrl({
			redirectUri: "https://auth.test/session/oauth/federation/idp-a/callback",
			state: "s",
			codeVerifier: "v".repeat(43),
			nonce: "n",
		});
		const urlB = providers?.get("idp-b")?.buildAuthorizationUrl({
			redirectUri: "https://auth.test/session/oauth/federation/idp-b/callback",
			state: "s",
			codeVerifier: "v".repeat(43),
			nonce: "n",
		});
		expect(urlA?.href.startsWith("https://idp-a.test/authorize?")).toBe(true);
		expect(urlA?.searchParams.get("client_id")).toBe("client-a");
		expect(urlB?.href.startsWith("https://idp-b.test/tenant/b/authorize?")).toBe(true);
		expect(urlB?.searchParams.get("client_id")).toBe("client-b");

		const policies = (handle.components as Record<string, unknown>)
			.federationRedirectPolicyResolver as
			| ReadonlyMap<string, FederationRedirectPolicy>
			| undefined;
		expect([...(policies?.keys() ?? [])].sort()).toEqual(["idp-a", "idp-b"]);

		await handle.dispose();
	});

	it("a discovery failure on any instance is fatal at boot and names it", async () => {
		const idpA = await createFakeIdp({ issuer: "https://idp-a.test" });
		const idpB = await createFakeIdp({ issuer: "https://idp-b.test" });
		idpB.discoveryStatus = 500;
		const configs = defineModule({
			name: "test-oidc-configs",
			provides: {
				oidcFederationConfigs: () => ({
					"idp-a": configFor(idpA, "idp-a"),
					"idp-b": configFor(idpB, "idp-b"),
				}),
			},
		});
		await expect(
			createApp({
				modules: [
					oidcFederationModule("idp-a"),
					oidcFederationModule("idp-b"),
					configs,
					activatorModule,
				],
				bootstrapComponents: minBoot,
			}),
		).rejects.toThrow(/OIDC federation "idp-b"[\s\S]*discovery/);
	});

	it("an instance without a config entry refuses to boot", async () => {
		const idpA = await createFakeIdp({ issuer: "https://idp-a.test" });
		const configs = defineModule({
			name: "test-oidc-configs",
			provides: {
				oidcFederationConfigs: () => ({ "idp-a": configFor(idpA, "idp-a") }),
			},
		});
		await expect(
			createApp({
				modules: [
					oidcFederationModule("idp-a"),
					oidcFederationModule("idp-b"),
					configs,
					activatorModule,
				],
				bootstrapComponents: minBoot,
			}),
		).rejects.toThrow(/oidcFederationConfigs[\s\S]*"idp-b"/);
	});
});
