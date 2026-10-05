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
 * The `federationSettings` slot: core's view of `core.federations` — every
 * entry by name, enabled or not, with what core reads of it (its type,
 * whether it is on, whether its upstream `amr` counts, its callback URL, and
 * the upstream issuer and client id as configured), never a secret. Core
 * fills it from the configuration before any provider runs, for every
 * composition, and reserves the key, so a module reads the federations from
 * its dependencies rather than from `config`. Its contract suite, run over
 * what core fills, and its test double.
 */

import { describe, expect, expectTypeOf, it } from "vitest";
import { federationSettingsOf } from "#/boot/federation-settings.mjs";
import type { BootstrapMap } from "#/boot/types.mjs";
import { federationsOf } from "#/federations/configured.mjs";
import type { ConfiguredFederation, FederationSettings } from "#/federations/settings.mjs";
import { createApp, defineModule, type ProviderDeps } from "#/index.mjs";
import type { ComponentMap } from "#/modules/manifest/component-map.mjs";
import { federationTypeForTests } from "#/testing/fixtures/federationType.mjs";
import { coreConfigForTests, makeValidCoreConfig } from "#/testing/fixtures/valid-config.mjs";
import { createTestFederationSettings, federationSettingsContract } from "#/testing/index.mjs";
import {
	federationCallbackMeetsFreshness,
	federationTrustsUpstreamAmr,
} from "#/user-sessions/authentication.mjs";

const RULES = [
	"every entry names its type",
	"enabled and trustsUpstreamAmr are booleans, and an upstream amr counts only for an enabled entry",
	"callbackMeetsFreshness is a boolean, true only for an enabled entry",
	"callbackURL, issuer and clientId are non-empty strings where present, and an enabled entry has a callbackURL",
	"an entry carries only what core reads of it",
	"the settings inherit no member",
	"the settings are frozen",
];

/** The names of the cases `settings` fails. */
const failing = async (settings: unknown): Promise<string[]> => {
	const failed: string[] = [];
	for (const { name, run } of federationSettingsContract({
		build: () => settings as FederationSettings,
	})) {
		try {
			await run();
		} catch {
			failed.push(name);
		}
	}
	return failed;
};

/** `entries` as the slot holds them: a frozen map that inherits nothing, each entry frozen. */
const settingsOf = (entries: Record<string, Record<string, unknown>>): unknown =>
	Object.freeze(
		Object.assign(
			Object.create(null) as object,
			Object.fromEntries(
				Object.entries(entries).map(([name, entry]) => [name, Object.freeze({ ...entry })]),
			),
		),
	);

const ON = {
	type: "oidc",
	enabled: true,
	trustsUpstreamAmr: false,
	callbackMeetsFreshness: false,
	callbackURL: "https://auth.example/session/oauth/federation/okta/callback",
	issuer: "https://okta.example",
	clientId: "okta-client",
};

describe("the federationSettings slot", () => {
	it("is optional, and holds core's view of core.federations", () => {
		expectTypeOf<ComponentMap["federationSettings"]>().toEqualTypeOf<
			FederationSettings | undefined
		>();
		expectTypeOf<
			ProviderDeps<"federationSettings">["federationSettings"]
		>().toEqualTypeOf<FederationSettings>();
		expectTypeOf<FederationSettings>().toEqualTypeOf<
			Readonly<Record<string, ConfiguredFederation>>
		>();
		expect(true).toBe(true);
	});

	it("carries no secret of an entry in its type", () => {
		expectTypeOf<keyof ConfiguredFederation>().toEqualTypeOf<
			| "type"
			| "enabled"
			| "trustsUpstreamAmr"
			| "callbackMeetsFreshness"
			| "callbackURL"
			| "issuer"
			| "clientId"
		>();
		expect(true).toBe(true);
	});
});

describe("federationSettingsContract", () => {
	it("names its rules", () => {
		expect(
			federationSettingsContract({ build: () => createTestFederationSettings() }).map(
				(c) => c.name,
			),
		).toEqual(RULES);
	});

	it("keeps them for an empty map, an enabled entry and a disabled one", async () => {
		expect(await failing(settingsOf({}))).toEqual([]);
		expect(await failing(settingsOf({ okta: ON }))).toEqual([]);
		expect(
			await failing(
				settingsOf({
					okta: ON,
					google: {
						type: "google",
						enabled: false,
						trustsUpstreamAmr: false,
						callbackMeetsFreshness: false,
					},
					trusted: { ...ON, trustsUpstreamAmr: true },
					meets: { ...ON, callbackMeetsFreshness: true },
				}),
			),
		).toEqual([]);
	});

	it("fails the first for an entry without a type, or with an empty one", async () => {
		for (const type of [undefined, "", 1]) {
			expect(await failing(settingsOf({ okta: { ...ON, type } }))).toEqual([RULES[0]]);
		}
	});

	it("fails the second for a switch that is not a boolean, or trust beside a disabled entry", async () => {
		for (const entry of [
			{ ...ON, enabled: "true" },
			{ ...ON, enabled: undefined },
			{ ...ON, trustsUpstreamAmr: 1 },
			{ type: "oidc", enabled: false, trustsUpstreamAmr: true, callbackMeetsFreshness: false },
		]) {
			expect(await failing(settingsOf({ okta: entry }))).toEqual([RULES[1]]);
		}
	});

	it("fails the third for a freshness switch that is absent or not a boolean, or true beside a disabled entry", async () => {
		const { callbackMeetsFreshness: _omitted, ...without } = ON;
		for (const entry of [
			without,
			{ ...ON, callbackMeetsFreshness: "true" },
			{ ...ON, callbackMeetsFreshness: undefined },
			{ type: "oidc", enabled: false, trustsUpstreamAmr: false, callbackMeetsFreshness: true },
		]) {
			expect(await failing(settingsOf({ okta: entry }))).toEqual([RULES[2]]);
		}
	});

	it("fails the fourth for an empty or non-string URL or identity, or an enabled entry without a callbackURL", async () => {
		for (const entry of [
			{ ...ON, callbackURL: "" },
			{ ...ON, issuer: 1 },
			{ ...ON, clientId: "" },
			{ type: "oidc", enabled: true, trustsUpstreamAmr: false, callbackMeetsFreshness: false },
		]) {
			expect(await failing(settingsOf({ okta: entry }))).toEqual([RULES[3]]);
		}
	});

	it("fails the fifth for a member core does not read, a secret above all", async () => {
		for (const extra of [{ clientSecret: "s3cret" }, { privateKey: "pem" }, { scopes: "openid" }]) {
			expect(await failing(settingsOf({ okta: { ...ON, ...extra } }))).toEqual([RULES[4]]);
		}
	});

	it("fails the sixth for a map with a prototype, where a name like constructor would read as an entry", async () => {
		expect(await failing(Object.freeze({ okta: Object.freeze({ ...ON }) }))).toEqual([RULES[5]]);
	});

	it("fails the last for settings a reader could change", async () => {
		const map = Object.assign(Object.create(null) as object, { okta: Object.freeze({ ...ON }) });
		expect(await failing(map)).toEqual([RULES[6]]);
		expect(
			await failing(
				Object.freeze(Object.assign(Object.create(null) as object, { okta: { ...ON } })),
			),
		).toEqual([RULES[6]]);
	});
});

describe("createTestFederationSettings", () => {
	it("keeps a freshness switch a test sets on an enabled entry", async () => {
		const settings = createTestFederationSettings({
			okta: { type: "oidc", callbackMeetsFreshness: true },
		});
		expect(settings.okta?.callbackMeetsFreshness).toBe(true);
		expect(await failing(settings)).toEqual([]);
	});

	it("answers an empty map unless told otherwise, keeping the contract", async () => {
		const settings = createTestFederationSettings();
		expect(Object.keys(settings)).toEqual([]);
		expect(await failing(settings)).toEqual([]);
	});

	it("fills an entry a test names, enabled with a callback URL unless it says otherwise", async () => {
		const settings = createTestFederationSettings({
			okta: { type: "oidc", issuer: "https://okta.example", clientId: "okta-client" },
			google: { type: "google", enabled: false },
		});
		expect(settings.okta).toEqual({
			type: "oidc",
			enabled: true,
			trustsUpstreamAmr: false,
			callbackMeetsFreshness: false,
			callbackURL: "https://auth.test/session/oauth/federation/okta/callback",
			issuer: "https://okta.example",
			clientId: "okta-client",
		});
		expect(settings.google).toEqual({
			type: "google",
			enabled: false,
			trustsUpstreamAmr: false,
			callbackMeetsFreshness: false,
		});
		expect(await failing(settings)).toEqual([]);
	});
});

// ---------------------------------------------------------------------------
// Core fills it
// ---------------------------------------------------------------------------

/** A valid core configuration whose `core.federations` is `federations`, when given. */
const bootstrap = (
	federations: Record<string, unknown> | undefined,
	extra: Record<string, unknown> = {},
): BootstrapMap =>
	({
		config:
			federations === undefined
				? makeValidCoreConfig()
				: {
						...makeValidCoreConfig(),
						...coreConfigForTests({ federations: federations as never }),
					},
		pathResolver: (s: string) => s,
		...extra,
	}) as unknown as BootstrapMap;

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

/** A module that records the settings its provider was handed, before any other provider it does not depend on. */
const providerReading = (seen: unknown[]) =>
	defineModule({
		name: "test:provider-reading-federation-settings",
		requires: ["federationSettings"] as const,
		provides: {
			testFederationSettingsReader: (deps: ProviderDeps<"federationSettings">) => {
				seen.push(deps.federationSettings);
				return { kind: "reader" };
			},
		} as never,
	});

/** A module whose route records the settings its factory was handed. */
const routeReading = (seen: unknown[]) =>
	defineModule({
		name: "test:route-reading-federation-settings",
		requires: ["federationSettings", "testFederationSettingsReader"] as never,
		contributes: {
			routes: [
				(deps: ProviderDeps<"federationSettings">) => {
					seen.push(deps.federationSettings);
					return {
						id: "test-route-reading-federation-settings",
						mountPath: "/__test-route-reading-federation-settings__",
						handler: ((_req: unknown, _res: unknown, next: () => void) => next()) as never,
					};
				},
			],
		},
	});

/** An entry the `oidc` stand-in type handles, with a secret beside what core reads. */
const OIDC_ENTRY = {
	enabled: true,
	type: "oidc",
	callbackURL: "https://auth.example/session/oauth/federation/okta/callback",
	issuer: "https://okta.example",
	clientId: "okta-client",
	clientSecret: "okta-secret-value",
	privateKey: "-----BEGIN PRIVATE KEY-----",
	scopes: ["openid", "email"],
	trustUpstreamAmr: true,
	callbackMeetsFreshness: true,
};

/** Every federation an operator can write, as core's schema accepts it, and what the slot holds of it. */
const ACCEPTED: readonly (readonly [
	string,
	readonly Parameters<typeof createApp>[0]["modules"][number][],
	Record<string, unknown> | undefined,
	Record<string, ConfiguredFederation>,
])[] = [
	["no federations at all", [], undefined, {}],
	["an empty map", [], {}, {}],
	[
		"a disabled entry, with no type module installed",
		[],
		{
			google: {
				enabled: false,
				type: "google",
				clientId: "google-client",
				clientSecret: "google-secret-value",
				trustUpstreamAmr: true,
				callbackMeetsFreshness: true,
			},
		},
		{
			google: {
				type: "google",
				enabled: false,
				trustsUpstreamAmr: false,
				callbackMeetsFreshness: false,
				clientId: "google-client",
			},
		},
	],
	[
		"an enabled entry its type module handles, and a disabled one beside it",
		[federationTypeForTests("oidc"), federationStores],
		{
			okta: OIDC_ENTRY,
			legacy: {
				enabled: "false",
				type: "oidc",
				issuer: "https://legacy.example",
				clientId: "",
				callbackURL: "https://auth.example/session/oauth/federation/legacy/callback",
			},
		},
		{
			okta: {
				type: "oidc",
				enabled: true,
				trustsUpstreamAmr: true,
				callbackMeetsFreshness: true,
				callbackURL: "https://auth.example/session/oauth/federation/okta/callback",
				issuer: "https://okta.example",
				clientId: "okta-client",
			},
			legacy: {
				type: "oidc",
				enabled: false,
				trustsUpstreamAmr: false,
				callbackMeetsFreshness: false,
				callbackURL: "https://auth.example/session/oauth/federation/legacy/callback",
				issuer: "https://legacy.example",
			},
		},
	],
	[
		"an enabled entry as an environment variable spells its switches",
		[federationTypeForTests("oidc"), federationStores],
		{
			okta: {
				...OIDC_ENTRY,
				enabled: "1",
				trustUpstreamAmr: "false",
				callbackMeetsFreshness: "false",
			},
		},
		{
			okta: {
				type: "oidc",
				enabled: true,
				trustsUpstreamAmr: false,
				callbackMeetsFreshness: false,
				callbackURL: "https://auth.example/session/oauth/federation/okta/callback",
				issuer: "https://okta.example",
				clientId: "okta-client",
			},
		},
	],
];

describe("core fills federationSettings from the configuration's core.federations", () => {
	it.each(ACCEPTED)("fills it for %s", async (_what, modules, federations, expected) => {
		const handle = await createApp({ modules, bootstrapComponents: bootstrap(federations) });
		try {
			const filled = handle.components.federationSettings;
			expect(filled).toEqual(expected);
			expect(Object.keys(filled ?? {})).toEqual(Object.keys(expected));
		} finally {
			await handle.dispose();
		}
	});

	it.each(ACCEPTED)(
		"fills it with core's reading of the configuration it parsed, for %s",
		async (_what, modules, federations) => {
			const handle = await createApp({ modules, bootstrapComponents: bootstrap(federations) });
			try {
				const config = handle.components.config;
				const filled = handle.components.federationSettings as FederationSettings;
				expect(filled).toEqual(federationSettingsOf(config));
				expect(Object.keys(filled)).toEqual(Object.keys(federationsOf(config)));
				for (const [name, entry] of Object.entries(federationsOf(config))) {
					const written = entry as { readonly enabled: unknown; readonly type: unknown };
					expect(filled[name]?.enabled).toBe(written.enabled === true);
					expect(filled[name]?.type).toBe(written.type);
					expect(filled[name]?.trustsUpstreamAmr).toBe(federationTrustsUpstreamAmr(config, name));
					expect(filled[name]?.callbackMeetsFreshness).toBe(
						federationCallbackMeetsFreshness(config, name),
					);
				}
			} finally {
				await handle.dispose();
			}
		},
	);

	it.each(ACCEPTED)("keeps the slot's contract for %s", async (_what, modules, federations) => {
		const handle = await createApp({ modules, bootstrapComponents: bootstrap(federations) });
		try {
			const filled = handle.components.federationSettings;
			expect(Object.isFrozen(filled)).toBe(true);
			for (const { name, run } of federationSettingsContract({
				build: () => filled as FederationSettings,
			})) {
				await expect(run(), name).resolves.toBeUndefined();
			}
		} finally {
			await handle.dispose();
		}
	});

	it.each(ACCEPTED)(
		"carries no secret of an entry, for %s",
		async (_what, modules, federations) => {
			const handle = await createApp({ modules, bootstrapComponents: bootstrap(federations) });
			try {
				const filled = JSON.stringify(handle.components.federationSettings);
				for (const secret of [
					"secret-value",
					"PRIVATE KEY",
					"clientSecret",
					"privateKey",
					"scopes",
				]) {
					expect(filled).not.toContain(secret);
				}
			} finally {
				await handle.dispose();
			}
		},
	);

	it("hands a provider that requires it, and a route, the settings it fills", async () => {
		const seen: unknown[] = [];
		const handle = await createApp({
			modules: [
				federationTypeForTests("oidc"),
				federationStores,
				providerReading(seen),
				routeReading(seen),
			],
			bootstrapComponents: bootstrap({ okta: OIDC_ENTRY }),
		});
		try {
			expect(seen).toHaveLength(2);
			expect(seen[0]).toBe(handle.components.federationSettings);
			expect(seen[1]).toBe(handle.components.federationSettings);
			expect((seen[0] as FederationSettings).okta?.enabled).toBe(true);
		} finally {
			await handle.dispose();
		}
	});

	it("reads a name no entry has as absent, Object.prototype's members included", async () => {
		const handle = await createApp({ modules: [], bootstrapComponents: bootstrap({}) });
		try {
			const filled = handle.components.federationSettings as FederationSettings;
			for (const name of ["constructor", "toString", "__proto__", "hasOwnProperty"]) {
				expect(filled[name]).toBeUndefined();
			}
		} finally {
			await handle.dispose();
		}
	});
});

// ---------------------------------------------------------------------------
// The key is reserved
// ---------------------------------------------------------------------------

describe("the federationSettings key is reserved", () => {
	const settings = createTestFederationSettings({ okta: { type: "oidc" } });
	const provider = defineModule({
		name: "test:provides-federation-settings",
		provides: { federationSettings: () => settings },
	});
	const REMEDY =
		"Set core.federations in the configuration instead: boot fills federationSettings from it.";

	it("refuses a module that provides it, naming the module", async () => {
		await expect(
			createApp({ modules: [provider], bootstrapComponents: bootstrap(undefined) }),
		).rejects.toMatchObject({
			name: "BootError",
			reason: "synthetic-key-collision",
			details: {
				reason: "synthetic-key-collision",
				componentKey: "federationSettings",
				source: "module-provides",
				module: "test:provides-federation-settings",
			},
		});
	});

	it("refuses bootstrapComponents that set it", async () => {
		await expect(
			createApp({
				modules: [],
				bootstrapComponents: bootstrap(undefined, { federationSettings: settings }),
			}),
		).rejects.toMatchObject({
			name: "BootError",
			reason: "synthetic-key-collision",
			details: {
				reason: "synthetic-key-collision",
				componentKey: "federationSettings",
				source: "bootstrapComponents",
			},
		});
	});

	it("refuses overrideComponents that set it", async () => {
		await expect(
			createApp({
				modules: [],
				bootstrapComponents: bootstrap(undefined),
				overrideComponents: { federationSettings: settings },
			}),
		).rejects.toMatchObject({
			name: "BootError",
			reason: "synthetic-key-collision",
			details: {
				reason: "synthetic-key-collision",
				componentKey: "federationSettings",
				source: "overrideComponents",
			},
		});
	});

	it("tells whoever set it to set core.federations instead, from every source", async () => {
		for (const boot of [
			createApp({ modules: [provider], bootstrapComponents: bootstrap(undefined) }),
			createApp({
				modules: [],
				bootstrapComponents: bootstrap(undefined, { federationSettings: settings }),
			}),
			createApp({
				modules: [],
				bootstrapComponents: bootstrap(undefined),
				overrideComponents: { federationSettings: settings },
			}),
		]) {
			const err = (await boot.catch((thrown: unknown) => thrown)) as Error;
			expect(err.message).toContain(REMEDY);
		}
	});
});
