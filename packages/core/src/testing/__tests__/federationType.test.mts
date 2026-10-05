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

/**
 * `federationTypeForTests`: the module a test installs so that boot handles
 * the `core.federations` entries of one type, as a federation package's
 * module would, without that package.
 */

import { describe, expect, it, vi } from "vitest";
import { createApp } from "#/boot/create-app.mjs";
import type { AppHandle, BootstrapMap } from "#/boot/types.mjs";
import type { FederationProvider } from "#/federations/types.mjs";
import { defineModule } from "#/modules/manifest/index.mjs";
import { federationTypeForTests, makeValidCoreConfig, withFederation } from "#/testing/index.mjs";

/** The six slots an enabled federation needs wired (`federation-stores-wiring`). */
const federationStores = defineModule({
	name: "test:federation-stores",
	provides: {
		userSessionStore: () => ({ kind: "stub" }),
		sessionRPRegistry: () => ({ kind: "stub" }),
		sessionFamilyIndex: () => ({ kind: "stub" }),
		sessionFederationIndex: () => ({ kind: "stub" }),
		federationTokenStore: () => ({ kind: "stub" }),
		refreshTokenFamilyRevocation: () => ({ kind: "stub" }),
	} as never,
});

const callbackURL = (name: string) => `https://auth.test/session/federation/${name}/callback`;

/** Core's valid configuration with `corp` and `partner` enabled entries of the type `acme`. */
function twoAcmeEntries(): Record<string, unknown> {
	const corp = withFederation(makeValidCoreConfig(), "corp", {
		type: "acme",
		callbackURL: callbackURL("corp"),
	});
	return withFederation(corp, "partner", { type: "acme", callbackURL: callbackURL("partner") });
}

const bootstrap = (config: Record<string, unknown>): BootstrapMap =>
	({ config, pathResolver: (s: string) => s }) as unknown as BootstrapMap;

/** The redirect-policy projection, by federation name. */
const redirectPolicies = (handle: AppHandle): ReadonlyMap<string, unknown> | undefined =>
	(handle.components as Record<string, unknown>).federationRedirectPolicyResolver as
		| ReadonlyMap<string, unknown>
		| undefined;

interface AcceptingPolicy {
	validateRedirect(url: string): unknown;
	resolveCallbackRedirect(session: { readonly redirectTo?: string }): unknown;
}

describe("federationTypeForTests", () => {
	it("is a module named after its type that contributes the type alone", () => {
		const module = federationTypeForTests("acme");

		expect(module.name).toBe("test-federation-type-acme");
		expect(Object.keys(module.contributes ?? {})).toEqual(["federationTypes"]);
		expect(Object.keys(module.contributes?.federationTypes ?? {})).toEqual(["acme"]);
	});

	it("boots each enabled entry of its type: a provider named after the entry, and a redirect policy that accepts, under its name", async () => {
		const handle = await createApp({
			modules: [federationStores, federationTypeForTests("acme")],
			bootstrapComponents: bootstrap(twoAcmeEntries()),
		});

		const providers = handle.components.federationProviders;
		expect([...(providers?.keys() ?? [])]).toEqual(["corp", "partner"]);
		const corp = providers?.get("corp");
		expect(corp?.name).toBe("corp");
		expect(providers?.get("partner")?.name).toBe("partner");
		expect(corp?.scope).toEqual(["openid"]);
		expect(
			corp?.buildAuthorizationUrl({ redirectUri: "r", state: "s", codeVerifier: "v" }),
		).toBeInstanceOf(URL);
		await expect(
			corp?.exchangeCode({ code: "c", redirectUri: "r", codeVerifier: "v" } as never),
		).resolves.toMatchObject({ sub: expect.any(String) });

		const policies = redirectPolicies(handle);
		expect([...(policies?.keys() ?? [])]).toEqual(["corp", "partner"]);
		const policy = policies?.get("corp") as AcceptingPolicy;
		expect(policy.validateRedirect("https://anywhere.test/")).toEqual({
			ok: true,
			value: undefined,
		});
		expect(policy.resolveCallbackRedirect({})).toEqual({ ok: true, value: "/" });
		await handle.dispose();
	});

	it("builds each entry's provider with the callback a test gives, handed the instance", async () => {
		const seen: unknown[] = [];
		const provider = vi.fn((instance: { readonly name: string }): FederationProvider => {
			seen.push(instance);
			return {
				name: instance.name,
				scope: ["openid", "email"],
				buildAuthorizationUrl: () => new URL(`https://${instance.name}.idp.test/authorize`),
				exchangeCode: async () => ({ issuer: "https://idp.test", sub: "u", expiresAt: null }),
			};
		});

		const handle = await createApp({
			modules: [federationStores, federationTypeForTests("acme", { provider })],
			bootstrapComponents: bootstrap(twoAcmeEntries()),
		});

		expect(provider).toHaveBeenCalledTimes(2);
		expect(seen[0]).toEqual({
			name: "corp",
			callbackURL: callbackURL("corp"),
			entry: { clientId: "corp-client", clientSecret: "corp-secret" },
		});
		expect(handle.components.federationProviders?.get("partner")?.scope).toEqual([
			"openid",
			"email",
		]);
		await handle.dispose();
	});

	it("registers the redirect policy the callback a test gives answers for each entry", async () => {
		const redirectPolicy = (instance: { readonly name: string }) => ({ for: instance.name });

		const handle = await createApp({
			modules: [federationStores, federationTypeForTests("acme", { redirectPolicy })],
			bootstrapComponents: bootstrap(twoAcmeEntries()),
		});

		expect(redirectPolicies(handle)?.get("corp")).toEqual({ for: "corp" });
		expect(redirectPolicies(handle)?.get("partner")).toEqual({ for: "partner" });
		await handle.dispose();
	});

	it("registers nothing for a disabled entry of its type", async () => {
		const provider = vi.fn();
		const redirectPolicy = vi.fn();
		const config = makeValidCoreConfig();

		const handle = await createApp({
			modules: [federationTypeForTests("acme", { provider, redirectPolicy })],
			bootstrapComponents: bootstrap({
				...config,
				core: {
					...config.core,
					federations: { corp: { enabled: false, type: "acme", callbackURL: callbackURL("corp") } },
				},
			}),
		});

		expect(provider).not.toHaveBeenCalled();
		expect(redirectPolicy).not.toHaveBeenCalled();
		expect(handle.components.federationProviders?.get("corp")).toBeUndefined();
		expect(redirectPolicies(handle)?.get("corp")).toBeUndefined();
		await handle.dispose();
	});
});
