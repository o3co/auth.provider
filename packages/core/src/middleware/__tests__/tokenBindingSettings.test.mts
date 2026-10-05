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
 * The `tokenBindingSettings` slot: the settings across every mechanism at
 * core's token-binding extension point — the dispatch policy and whether a
 * confidential client's refresh token is bound — as core's one reader of
 * `core.tokenBinding` (`resolveTokenBindingSettings`) answers them. Core fills
 * it from the configuration before any provider runs, for every composition,
 * and reserves the key, so a grant reads the settings from its dependencies
 * rather than from `config`. Its contract suite, run over what core fills, and
 * its test double.
 */

import { describe, expect, expectTypeOf, it } from "vitest";
import type { BootstrapMap } from "#/boot/types.mjs";
import type { GrantDependencies, GrantHandler } from "#/grants/types.mjs";
import { createApp, defineModule, type ProviderDeps } from "#/index.mjs";
import {
	resolveTokenBindingSettings,
	type TokenBindingSettings,
} from "#/middleware/tokenBinding.mjs";
import type { ComponentMap } from "#/modules/manifest/component-map.mjs";
import { makeValidCoreConfig } from "#/testing/fixtures/valid-config.mjs";
import {
	createTestOAuthTokenSettings,
	createTestTokenBindingSettings,
	tokenBindingSettingsContract,
} from "#/testing/index.mjs";

const RULES = [
	"dispatchPolicy is intent-explicit or strict-mutual-exclusion",
	"bindConfidentialClientRefreshTokens is true or false",
	"the settings are frozen",
];

/** The names of the cases `settings` fails. */
const failing = async (settings: unknown): Promise<string[]> => {
	const failed: string[] = [];
	for (const { name, run } of tokenBindingSettingsContract({
		build: () => settings as TokenBindingSettings,
	})) {
		try {
			await run();
		} catch {
			failed.push(name);
		}
	}
	return failed;
};

describe("the tokenBindingSettings slot", () => {
	it("is optional, and holds core's token-binding settings", () => {
		expectTypeOf<ComponentMap["tokenBindingSettings"]>().toEqualTypeOf<
			TokenBindingSettings | undefined
		>();
		expectTypeOf<
			ProviderDeps<"tokenBindingSettings">["tokenBindingSettings"]
		>().toEqualTypeOf<TokenBindingSettings>();
		expect(true).toBe(true);
	});

	it("is a grant dependency, optional beside config", () => {
		expectTypeOf<GrantDependencies["tokenBindingSettings"]>().toEqualTypeOf<
			TokenBindingSettings | undefined
		>();
		expectTypeOf<GrantDependencies["config"]>().not.toBeUndefined();
		expect(true).toBe(true);
	});
});

describe("tokenBindingSettingsContract", () => {
	it("names its rules", () => {
		expect(
			tokenBindingSettingsContract({ build: () => createTestTokenBindingSettings() }).map(
				(c) => c.name,
			),
		).toEqual(RULES);
	});

	it("keeps them for every setting the configuration can state", async () => {
		for (const dispatchPolicy of ["intent-explicit", "strict-mutual-exclusion"] as const) {
			for (const bindConfidentialClientRefreshTokens of [true, false]) {
				expect(
					await failing(Object.freeze({ dispatchPolicy, bindConfidentialClientRefreshTokens })),
				).toEqual([]);
			}
		}
	});

	it("fails the first for a policy core does not arbitrate by, absence included", async () => {
		for (const dispatchPolicy of ["Intent-Explicit", "", undefined, null, "first-wins"]) {
			expect(
				await failing(
					Object.freeze({ dispatchPolicy, bindConfidentialClientRefreshTokens: false }),
				),
			).toEqual([RULES[0]]);
		}
	});

	it("fails the second for anything but a boolean, absence included", async () => {
		for (const bindConfidentialClientRefreshTokens of ["true", 1, undefined, null]) {
			expect(
				await failing(
					Object.freeze({ dispatchPolicy: "intent-explicit", bindConfidentialClientRefreshTokens }),
				),
			).toEqual([RULES[1]]);
		}
	});

	it("fails the third for settings a reader could change", async () => {
		expect(
			await failing({
				dispatchPolicy: "intent-explicit",
				bindConfidentialClientRefreshTokens: false,
			}),
		).toEqual([RULES[2]]);
	});
});

describe("createTestTokenBindingSettings", () => {
	it("answers what an unset core.tokenBinding reads as, frozen", async () => {
		const settings = createTestTokenBindingSettings();
		expect(settings).toEqual(resolveTokenBindingSettings({}));
		expect(await failing(settings)).toEqual([]);
	});

	it("takes what a test replaces", () => {
		expect(
			createTestTokenBindingSettings({
				dispatchPolicy: "strict-mutual-exclusion",
				bindConfidentialClientRefreshTokens: true,
			}),
		).toEqual({
			dispatchPolicy: "strict-mutual-exclusion",
			bindConfidentialClientRefreshTokens: true,
		});
	});
});

// ---------------------------------------------------------------------------
// Core fills it
// ---------------------------------------------------------------------------

/** Every `core.tokenBinding` core's schema accepts, and the settings it states. */
const ACCEPTED: readonly (readonly [
	string,
	Record<string, unknown> | undefined,
	TokenBindingSettings,
])[] = [
	[
		"no tokenBinding section",
		undefined,
		{ dispatchPolicy: "intent-explicit", bindConfidentialClientRefreshTokens: false },
	],
	[
		"dispatchPolicy = intent-explicit",
		{ dispatchPolicy: "intent-explicit" },
		{ dispatchPolicy: "intent-explicit", bindConfidentialClientRefreshTokens: false },
	],
	[
		"dispatchPolicy = strict-mutual-exclusion",
		{ dispatchPolicy: "strict-mutual-exclusion" },
		{ dispatchPolicy: "strict-mutual-exclusion", bindConfidentialClientRefreshTokens: false },
	],
	[
		"bindConfidentialClientRefreshTokens = true",
		{ dispatchPolicy: "intent-explicit", bindConfidentialClientRefreshTokens: true },
		{ dispatchPolicy: "intent-explicit", bindConfidentialClientRefreshTokens: true },
	],
	[
		"bindConfidentialClientRefreshTokens = false",
		{ dispatchPolicy: "strict-mutual-exclusion", bindConfidentialClientRefreshTokens: false },
		{ dispatchPolicy: "strict-mutual-exclusion", bindConfidentialClientRefreshTokens: false },
	],
];

/** A valid core configuration with `core.tokenBinding` as given. */
const configWith = (tokenBinding: Record<string, unknown> | undefined): Record<string, unknown> => {
	const base = makeValidCoreConfig();
	return tokenBinding === undefined ? base : { ...base, core: { ...base.core, tokenBinding } };
};

/** A valid core configuration with `core.tokenBinding` as given, and whatever else `extra` holds. */
const bootstrap = (
	tokenBinding: Record<string, unknown> | undefined,
	extra: Record<string, unknown> = {},
): BootstrapMap =>
	({
		config: configWith(tokenBinding),
		pathResolver: (s: string) => s,
		...extra,
	}) as unknown as BootstrapMap;

const GRANT_TYPE = "urn:test:token-binding-settings";

/** A grant module whose grant records the settings its factory was handed, and nothing of `config`. */
const grantModule = (seen: unknown[]) => {
	const grant = (deps: Pick<GrantDependencies, "tokenBindingSettings">): GrantHandler => {
		seen.push(deps.tokenBindingSettings);
		return { handle: async () => ({ result: { status: 200, tokens: {} as never } }) };
	};
	return defineModule({
		name: "test:token-binding-settings-grant",
		requires: ["tokenBindingSettings"] as const,
		contributes: { grants: { [GRANT_TYPE]: grant } },
	});
};

/** A stand-in for the oauth module: it provides `oauthTokenSettings`, and names it authoritative. */
const oauthStandIn = defineModule({
	name: "test:oauth-token-settings-owner",
	provides: { oauthTokenSettings: () => createTestOAuthTokenSettings() },
	authoritative: ["oauthTokenSettings"],
});

/** A route that requires `oauthTokenSettings`, so that the stand-in's provider runs at boot. */
const oauthReader = defineModule({
	name: "test:oauth-token-settings-reader",
	requires: ["oauthTokenSettings"] as const,
	contributes: {
		routes: [
			() => ({
				id: "test-oauth-token-settings-reader",
				mountPath: "/__test-oauth-token-settings-reader__",
				handler: ((_req: unknown, _res: unknown, next: () => void) => next()) as never,
			}),
		],
	},
});

describe("core fills tokenBindingSettings from the configuration's core.tokenBinding", () => {
	it.each(ACCEPTED)(
		"fills it, without the oauth module, with what %s states: the resolver's answer over the configuration",
		async (_what, tokenBinding, expected) => {
			const handle = await createApp({ modules: [], bootstrapComponents: bootstrap(tokenBinding) });
			try {
				expect(handle.components.oauthTokenSettings).toBeUndefined();
				expect(handle.components.tokenBindingSettings).toEqual(expected);
				expect(handle.components.tokenBindingSettings).toEqual(
					resolveTokenBindingSettings(handle.components.config),
				);
			} finally {
				await handle.dispose();
			}
		},
	);

	it.each(ACCEPTED)(
		"fills it the same with the oauth module's slot held, for %s",
		async (_what, tokenBinding, expected) => {
			const handle = await createApp({
				modules: [oauthStandIn, oauthReader],
				bootstrapComponents: bootstrap(tokenBinding),
			});
			try {
				expect(handle.components.oauthTokenSettings).toBeDefined();
				expect(handle.components.tokenBindingSettings).toEqual(expected);
			} finally {
				await handle.dispose();
			}
		},
	);

	it.each(ACCEPTED)("keeps the slot's contract for %s", async (_what, tokenBinding) => {
		const handle = await createApp({ modules: [], bootstrapComponents: bootstrap(tokenBinding) });
		try {
			const filled = handle.components.tokenBindingSettings;
			expect(Object.isFrozen(filled)).toBe(true);
			for (const { name, run } of tokenBindingSettingsContract({
				build: () => filled as TokenBindingSettings,
			})) {
				await expect(run(), name).resolves.toBeUndefined();
			}
		} finally {
			await handle.dispose();
		}
	});

	it.each(ACCEPTED)(
		"hands a grant factory that requires it the settings %s states",
		async (_what, tokenBinding, expected) => {
			const seen: unknown[] = [];
			const handle = await createApp({
				modules: [grantModule(seen)],
				bootstrapComponents: bootstrap(tokenBinding),
			});
			try {
				expect(seen).toEqual([expected]);
				expect(seen[0]).toBe(handle.components.tokenBindingSettings);
				expect(handle.components.grantHandlerResolver?.get(GRANT_TYPE)).toBeDefined();
			} finally {
				await handle.dispose();
			}
		},
	);

	it("hands a contribution factory that lists it as optional the same settings", async () => {
		const seen: unknown[] = [];
		const handle = await createApp({
			modules: [
				defineModule({
					name: "test:route-reading-token-binding-settings",
					optional: ["tokenBindingSettings"] as const,
					contributes: {
						routes: [
							(deps) => {
								seen.push(deps.tokenBindingSettings);
								return {
									id: "test-route-reading-token-binding-settings",
									mountPath: "/__test-route-reading-token-binding-settings__",
									handler: ((_req: unknown, _res: unknown, next: () => void) => next()) as never,
								};
							},
						],
					},
				}),
			],
			bootstrapComponents: bootstrap({
				dispatchPolicy: "strict-mutual-exclusion",
				bindConfidentialClientRefreshTokens: true,
			}),
		});
		try {
			expect(seen).toEqual([
				{ dispatchPolicy: "strict-mutual-exclusion", bindConfidentialClientRefreshTokens: true },
			]);
		} finally {
			await handle.dispose();
		}
	});
});

// ---------------------------------------------------------------------------
// The key is reserved
// ---------------------------------------------------------------------------

describe("the tokenBindingSettings key is reserved", () => {
	const settings = createTestTokenBindingSettings({ bindConfidentialClientRefreshTokens: true });
	const provider = defineModule({
		name: "test:provides-token-binding-settings",
		provides: { tokenBindingSettings: () => settings },
	});
	const REMEDY =
		"Set core.tokenBinding in the configuration instead: boot fills tokenBindingSettings from it.";

	it("refuses a module that provides it, naming the module", async () => {
		await expect(
			createApp({ modules: [provider], bootstrapComponents: bootstrap(undefined) }),
		).rejects.toMatchObject({
			name: "BootError",
			reason: "synthetic-key-collision",
			details: {
				reason: "synthetic-key-collision",
				componentKey: "tokenBindingSettings",
				source: "module-provides",
				module: "test:provides-token-binding-settings",
			},
		});
	});

	it("refuses bootstrapComponents that set it", async () => {
		await expect(
			createApp({
				modules: [],
				bootstrapComponents: bootstrap(undefined, { tokenBindingSettings: settings }),
			}),
		).rejects.toMatchObject({
			name: "BootError",
			reason: "synthetic-key-collision",
			details: {
				reason: "synthetic-key-collision",
				componentKey: "tokenBindingSettings",
				source: "bootstrapComponents",
			},
		});
	});

	it("refuses overrideComponents that set it", async () => {
		await expect(
			createApp({
				modules: [],
				bootstrapComponents: bootstrap(undefined),
				overrideComponents: { tokenBindingSettings: settings },
			}),
		).rejects.toMatchObject({
			name: "BootError",
			reason: "synthetic-key-collision",
			details: {
				reason: "synthetic-key-collision",
				componentKey: "tokenBindingSettings",
				source: "overrideComponents",
			},
		});
	});

	it("tells whoever set it to set core.tokenBinding instead, from every source", async () => {
		for (const boot of [
			createApp({ modules: [provider], bootstrapComponents: bootstrap(undefined) }),
			createApp({
				modules: [],
				bootstrapComponents: bootstrap(undefined, { tokenBindingSettings: settings }),
			}),
			createApp({
				modules: [],
				bootstrapComponents: bootstrap(undefined),
				overrideComponents: { tokenBindingSettings: settings },
			}),
		]) {
			const err = (await boot.catch((thrown: unknown) => thrown)) as Error;
			expect(err.message).toContain(REMEDY);
		}
	});
});
