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
 * The `federationTypes` contribution kind and the dispatch of
 * `core.federations`: a federation package declares, keyed by the `type` an
 * entry names, the schema of such an entry and the factories that build a
 * provider and its redirect policy from one entry. Boot parses every enabled
 * entry whose type a module registers with that schema at stage 1, and
 * registers the pair under the entry's name at stage 4. An enabled entry no
 * module handles — by its type, or by contributing `federations.<name>` —
 * refuses boot.
 */

import { describe, expect, it, vi } from "vitest";
import { z } from "zod";
import type { FederationProvider } from "../../federations/types.mjs";
import type { Module } from "../../modules/manifest/index.mjs";
import { defineModule } from "../../modules/manifest/index.mjs";
import { coreConfigForTests, makeValidCoreConfig } from "../../testing/fixtures/valid-config.mjs";
import { applyContributions } from "../apply-contributions.mjs";
import { createApp, mergeWithBuiltins } from "../create-app.mjs";
import { materializeComponents } from "../materialize-components.mjs";
import { planBoot } from "../plan-boot.mjs";
import type { AppHandle, BootstrapMap } from "../types.mjs";
import { BootError } from "../types.mjs";
import { validateManifests } from "../validate-manifests.mjs";

const bootWith = (extra: Record<string, unknown> = {}): BootstrapMap =>
	({
		config: { ...makeValidCoreConfig(), ...extra } as never,
		pathResolver: (s: string) => s,
	}) satisfies Record<string, unknown> as BootstrapMap;

/** A configuration whose `core.federations` is `federations`. */
const federationsConfig = (federations: Record<string, unknown>): BootstrapMap =>
	bootWith(coreConfigForTests({ federations: federations as never }));

const providerNamed = (name: string): FederationProvider => ({
	name,
	scope: ["openid"],
	buildAuthorizationUrl: () => new URL(`https://${name}.example/authorize`),
	exchangeCode: async () => ({ issuer: `https://${name}.example`, sub: "1", expiresAt: null }),
});

/** A redirect policy, tagged with the federation it was built for. */
const policyFor = (name: string) => ({
	for: name,
	validateRedirect: () => ({ ok: true as const, value: undefined }),
	resolveCallbackRedirect: () => ({ ok: true as const, value: "https://app.example" }),
});

const AcmeEntry = z.object({ issuer: z.string() });

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

/** A federation package handling the type `acme`, with spies on its factories. */
function acmePackage(
	options: {
		readonly entrySchema?: z.ZodType;
		readonly factory?: (deps: unknown, instance: { name: string }) => unknown;
		readonly redirectPolicy?: (deps: unknown, instance: { name: string }) => unknown;
	} = {},
) {
	const factory = vi.fn(
		options.factory ??
			((_deps: unknown, instance: { name: string }) => providerNamed(instance.name)),
	);
	const redirectPolicy = vi.fn(
		options.redirectPolicy ??
			((_deps: unknown, instance: { name: string }) => policyFor(instance.name)),
	);
	const module = defineModule({
		name: "federation-acme",
		requires: ["config"],
		contributes: {
			federationTypes: {
				acme: {
					entrySchema: options.entrySchema ?? AcmeEntry,
					factory: factory as never,
					redirectPolicy: redirectPolicy as never,
				},
			},
		},
	});
	return { module, factory, redirectPolicy };
}

/** A module contributing `federations.<name>` and its redirect policy directly. */
const directly = (moduleName: string, name: string): Module =>
	defineModule({
		name: moduleName,
		contributes: {
			federations: { [name]: () => providerNamed(name) },
			federationRedirectPolicies: { [name]: () => policyFor(name) },
		} as never,
	});

/** An enabled entry of `type` with a callback URL and `extra`. */
const enabledEntry = (
	type: string | undefined,
	name: string,
	extra: Record<string, unknown> = {},
) => ({
	enabled: true,
	...(type === undefined ? {} : { type }),
	callbackURL: `https://auth.example/session/federation/${name}/callback`,
	...extra,
});

/** Stages 1 to 4 over the built-in kinds, answering the `federationTypes` collector. */
async function registeredTypes(modules: readonly Module[], extra: Record<string, unknown> = {}) {
	const kinds = mergeWithBuiltins(undefined);
	const bootstrap = bootWith(extra);
	const validated = validateManifests({
		modules,
		bootstrapComponents: bootstrap,
		contributionKinds: kinds,
	});
	const plan = planBoot(validated, validated.bootstrapComponents, undefined);
	const material = await materializeComponents(
		plan,
		validated.bootstrapComponents,
		undefined,
		kinds,
	);
	await applyContributions(material, kinds);
	return kinds.federationTypes;
}

/** What `createApp` refused with, or a failure when it booted. */
async function refusal(promise: Promise<unknown>): Promise<BootError> {
	try {
		await promise;
	} catch (err) {
		expect(err).toBeInstanceOf(BootError);
		return err as BootError;
	}
	return expect.fail("boot should have been refused");
}

/** The redirect-policy projection, which the session package declares on the component map. */
const redirectPolicies = (handle: AppHandle): ReadonlyMap<string, unknown> | undefined =>
	(handle.components as Record<string, unknown>).federationRedirectPolicyResolver as
		| ReadonlyMap<string, unknown>
		| undefined;

describe("federationTypes — declared by type", () => {
	it("registers each declaration under its type, its schema kept and both factories bound to the module's deps", async () => {
		const { module, factory, redirectPolicy } = acmePackage();

		const types = await registeredTypes([module]);

		const registered = types?.get("acme");
		expect(registered?.entrySchema).toBe(AcmeEntry);
		expect([...(types?.entries() ?? [])].map(([type]) => type)).toEqual(["acme"]);
		// No entry names the type: nothing has asked for a provider.
		expect(factory).not.toHaveBeenCalled();
		expect(redirectPolicy).not.toHaveBeenCalled();
		const instance = {
			name: "corp",
			callbackURL: "https://auth.example/cb",
			entry: { issuer: "https://corp" },
		};
		const provider = await registered?.create(instance);
		expect(provider?.name).toBe("corp");
		expect(factory).toHaveBeenCalledWith(
			expect.objectContaining({ config: expect.anything() }),
			instance,
		);
		expect(await registered?.redirectPolicy(instance)).toMatchObject({ for: "corp" });
		expect(redirectPolicy).toHaveBeenCalledWith(
			expect.objectContaining({ config: expect.anything() }),
			instance,
		);
	});

	it("an override replaces a type's declaration", async () => {
		const replacement = z.object({ issuer: z.string(), tenant: z.string() });
		const replacer = defineModule({
			name: "federation-acme-replacement",
			overrides: {
				federationTypes: {
					acme: {
						entrySchema: replacement,
						factory: () => providerNamed("acme"),
						redirectPolicy: () => policyFor("acme"),
					},
				},
			},
		});

		const types = await registeredTypes([acmePackage().module, replacer]);

		expect(types?.get("acme")?.entrySchema).toBe(replacement);
	});
});

describe("core.federations — dispatched by type", () => {
	it("builds a provider and its redirect policy for each enabled entry of a registered type, under the entry's name", async () => {
		const { module, factory, redirectPolicy } = acmePackage({
			entrySchema: z.object({ issuer: z.string() }).strict(),
		});

		const handle = await createApp({
			modules: [federationStores, module],
			bootstrapComponents: federationsConfig({
				corp: enabledEntry("acme", "corp", {
					issuer: "https://corp.example",
					trustUpstreamAmr: true,
				}),
				partner: enabledEntry("acme", "partner", { issuer: "https://partner.example" }),
			}),
		});

		const providers = handle.components.federationProviders;
		expect([...(providers?.keys() ?? [])]).toEqual(["corp", "partner"]);
		expect(providers?.get("corp")?.name).toBe("corp");
		expect(providers?.get("partner")?.name).toBe("partner");
		expect(providers?.get("corp")).not.toBe(providers?.get("partner"));
		// Paired by construction: each name has the policy built from its own entry.
		expect(redirectPolicies(handle)?.get("corp")).toMatchObject({ for: "corp" });
		expect(redirectPolicies(handle)?.get("partner")).toMatchObject({ for: "partner" });
		// Core's keys are stripped before the type's strict schema reads the entry;
		// the callback URL, core's, comes beside it.
		expect(factory).toHaveBeenCalledTimes(2);
		expect(factory).toHaveBeenCalledWith(expect.objectContaining({ config: expect.anything() }), {
			name: "corp",
			callbackURL: "https://auth.example/session/federation/corp/callback",
			entry: { issuer: "https://corp.example" },
		});
		expect(redirectPolicy).toHaveBeenCalledWith(expect.anything(), {
			name: "partner",
			callbackURL: "https://auth.example/session/federation/partner/callback",
			entry: { issuer: "https://partner.example" },
		});
		await handle.dispose();
	});

	it("hands both factories one frozen instance, the entry as the type's schema answered it", async () => {
		const seen: unknown[] = [];
		const { module } = acmePackage({
			entrySchema: z.object({ issuer: z.string().transform((issuer) => new URL(issuer).origin) }),
			factory: (_deps, instance) => {
				seen.push(instance);
				return providerNamed(instance.name);
			},
			redirectPolicy: (_deps, instance) => {
				seen.push(instance);
				return policyFor(instance.name);
			},
		});

		const handle = await createApp({
			modules: [federationStores, module],
			bootstrapComponents: federationsConfig({
				corp: enabledEntry("acme", "corp", { issuer: "https://corp.example/path" }),
			}),
		});

		expect(seen).toHaveLength(2);
		expect(seen[0]).toBe(seen[1]);
		expect(Object.isFrozen(seen[0])).toBe(true);
		const { entry } = seen[0] as { entry: { issuer: string } };
		expect(entry).toEqual({ issuer: "https://corp.example" });
		expect(Object.isFrozen(entry)).toBe(true);
		await handle.dispose();
	});

	it("refuses an entry its type's schema refuses, naming the path the operator wrote, before any factory runs", async () => {
		const { module, factory } = acmePackage();

		const err = await refusal(
			createApp({
				modules: [federationStores, module],
				bootstrapComponents: federationsConfig({
					corp: enabledEntry("acme", "corp", { issuer: 42 }),
					partner: { enabled: true, type: "acme", issuer: "https://partner.example" },
				}),
			}),
		);

		expect(err.reason).toBe("config-validation-failed");
		expect(err.stage).toBe("validateManifests");
		expect(err.message).toContain("core.federations.corp.issuer");
		expect(err.message).toContain("core.federations.partner.callbackURL");
		expect(err.details).toMatchObject({
			reason: "config-validation-failed",
			issues: [
				expect.objectContaining({ path: ["core", "federations", "corp", "issuer"] }),
				expect.objectContaining({ path: ["core", "federations", "partner", "callbackURL"] }),
			],
			modules: [
				{ module: "federation-acme", schemaPath: "core.federations.corp" },
				{ module: "federation-acme", schemaPath: "core.federations.partner" },
			],
		});
		expect(factory).not.toHaveBeenCalled();
	});

	it("refuses an entry whose type's schema throws instead of answering", async () => {
		const { module } = acmePackage({
			entrySchema: z.object({ issuer: z.string() }).refine(async () => true),
		});

		const err = await refusal(
			createApp({
				modules: [federationStores, module],
				bootstrapComponents: federationsConfig({
					corp: enabledEntry("acme", "corp", { issuer: "https://corp.example" }),
				}),
			}),
		);

		expect(err.reason).toBe("config-validation-failed");
		expect(err.details).toMatchObject({
			issues: [expect.objectContaining({ path: ["core", "federations", "corp"] })],
			modules: [{ module: "federation-acme", schemaPath: "core.federations.corp" }],
		});
	});

	it("refuses a dispatched entry whose name is not one URL path segment", async () => {
		const { module, factory } = acmePackage();

		const err = await refusal(
			createApp({
				modules: [federationStores, module],
				bootstrapComponents: federationsConfig({
					"corp/idp": enabledEntry("acme", "corp", { issuer: "https://corp.example" }),
				}),
			}),
		);

		expect(err.reason).toBe("config-validation-failed");
		expect(err.stage).toBe("validateManifests");
		expect(err.details).toMatchObject({
			issues: [expect.objectContaining({ path: ["core", "federations", "corp/idp"] })],
			modules: [{ module: "federation-acme", schemaPath: "core.federations.corp/idp" }],
		});
		expect(err.message).toMatch(/URL path segment/);
		expect(factory).not.toHaveBeenCalled();
	});

	it.each<readonly [string, Parameters<typeof acmePackage>[0]]>([
		[
			"the provider factory throws",
			{
				factory: () => {
					throw new Error("issuer unreachable");
				},
			},
		],
		[
			"the redirect-policy factory throws",
			{
				redirectPolicy: () => {
					throw new Error("allowlist unreadable");
				},
			},
		],
		["the provider answers another name", { factory: () => providerNamed("other") }],
		["the provider factory answers nothing", { factory: () => undefined }],
		["the redirect-policy factory answers null", { redirectPolicy: () => null }],
	])(
		"refuses as a failed contribution when %s, running the cleanups first and registering neither",
		async (_label, options) => {
			const cleanup = vi.fn();
			const closing = defineModule({
				name: "test:closing",
				provides: { closingSlot: () => 1 },
				lifecycle: { closingSlot: { eager: true, cleanup } },
			} as never);
			const { module } = acmePackage(options);

			const err = await refusal(
				createApp({
					modules: [closing, federationStores, module],
					bootstrapComponents: federationsConfig({
						corp: enabledEntry("acme", "corp", { issuer: "https://corp.example" }),
					}),
				}),
			);

			expect(err.reason).toBe("contribute-factory-failed");
			expect(err.stage).toBe("applyContributions");
			expect(err.details).toMatchObject({
				reason: "contribute-factory-failed",
				module: "federation-acme",
				kind: "federations",
				name: "corp",
			});
			expect(err.message).toContain('"federation-acme"');
			expect(err.message).toContain('"corp"');
			expect(cleanup).toHaveBeenCalledOnce();
		},
	);

	it("neither parses nor refuses a disabled entry, whatever its type", async () => {
		const entrySchema = z.object({ issuer: z.string() });
		const safeParse = vi.spyOn(entrySchema, "safeParse");
		const parse = vi.spyOn(entrySchema, "parse");
		const { module, factory } = acmePackage({ entrySchema });

		const handle = await createApp({
			modules: [module],
			bootstrapComponents: federationsConfig({
				corp: { enabled: false, type: "acme", issuer: 42 },
				legacy: { enabled: false, type: "nobody", clientId: 7 },
				bare: { enabled: false },
			}),
		});

		expect(safeParse).not.toHaveBeenCalled();
		expect(parse).not.toHaveBeenCalled();
		expect(factory).not.toHaveBeenCalled();
		expect(handle.components.federationProviders?.get("corp")).toBeUndefined();
		await handle.dispose();
	});
});

describe("core.federations — an enabled entry no module handles refuses boot", () => {
	it("lists every enabled entry no module handles, by its type or by its name, with the types handled", async () => {
		const err = await refusal(
			createApp({
				modules: [federationStores, acmePackage().module, directly("federation-google", "google")],
				bootstrapComponents: federationsConfig({
					corp: enabledEntry("acme", "corp", { issuer: "https://corp.example" }),
					partner: enabledEntry("acmee", "partner", { clientSecret: "s3cr3t-value" }),
					legacy: enabledEntry(undefined, "legacy", { clientSecret: "s3cr3t-value" }),
					google: enabledEntry(undefined, "google"),
					off: { enabled: false, type: "nobody" },
				}),
			}),
		);

		expect(err.reason).toBe("federation-type-unhandled");
		expect(err.stage).toBe("validateManifests");
		expect(err.details).toEqual({
			reason: "federation-type-unhandled",
			unhandled: [{ federationName: "partner", type: "acmee" }, { federationName: "legacy" }],
			handled: ["acme"],
		});
		expect(err.message).toContain("core.federations.partner");
		expect(err.message).toContain('"acmee"');
		expect(err.message).toContain('federationTypes["acmee"]');
		expect(err.message).toContain("core.federations.legacy");
		expect(err.message).toContain('federations["legacy"]');
		expect(err.message).toContain('["acme"]');
		expect(err.message).toContain("enabled = false");
		expect(err.message).not.toContain("s3cr3t-value");
	});

	it("boots an enabled entry without a type that a module contributes by name", async () => {
		const handle = await createApp({
			modules: [federationStores, directly("federation-google", "google")],
			bootstrapComponents: federationsConfig({ google: enabledEntry(undefined, "google") }),
		});

		expect(handle.components.federationProviders?.get("google")?.name).toBe("google");
		await handle.dispose();
	});

	it("boots an enabled entry whose type no module registers while a module contributes its name, and parses nothing", async () => {
		const handle = await createApp({
			modules: [federationStores, directly("federation-google", "google")],
			bootstrapComponents: federationsConfig({
				google: enabledEntry("google", "google", { clientId: 7 }),
			}),
		});

		expect(handle.components.federationProviders?.get("google")?.name).toBe("google");
		await handle.dispose();
	});

	it("refuses an enabled entry without a type that no module contributes", async () => {
		const err = await refusal(
			createApp({
				modules: [federationStores],
				bootstrapComponents: federationsConfig({ google: enabledEntry(undefined, "google") }),
			}),
		);

		expect(err.reason).toBe("federation-type-unhandled");
		expect(err.details).toEqual({
			reason: "federation-type-unhandled",
			unhandled: [{ federationName: "google" }],
			handled: [],
		});
	});

	it("refuses an entry both dispatched by its type and contributed by its name", async () => {
		const { module, factory } = acmePackage();

		const err = await refusal(
			createApp({
				modules: [federationStores, module, directly("federation-corp", "corp")],
				bootstrapComponents: federationsConfig({
					corp: enabledEntry("acme", "corp", { issuer: "https://corp.example" }),
				}),
			}),
		);

		expect(err.reason).toBe("duplicate-contribute");
		expect(err.stage).toBe("validateManifests");
		expect(err.details).toEqual({
			reason: "duplicate-contribute",
			kind: "federations",
			identity: "corp",
			identityKind: "name",
			modules: ["federation-acme", "federation-corp"],
		});
		expect(factory).not.toHaveBeenCalled();
	});

	it("refuses the missing federation stores first", async () => {
		const err = await refusal(
			createApp({
				modules: [],
				bootstrapComponents: federationsConfig({ corp: enabledEntry("nobody", "corp") }),
			}),
		);

		expect(err.reason).toBe("federation-stores-incomplete");
	});

	it("treats a type a module switched off by its section registers as unhandled", async () => {
		const switchable = defineModule({
			name: "federation-acme",
			section: {
				schema: z.object({ enabled: z.boolean() }),
				isEnabled: (section: { enabled: boolean }) => section.enabled,
			},
			contributes: {
				federationTypes: {
					acme: {
						entrySchema: AcmeEntry,
						factory: () => providerNamed("corp"),
						redirectPolicy: () => policyFor("corp"),
					},
				},
			},
		} as never);

		const err = await refusal(
			createApp({
				modules: [federationStores, switchable],
				bootstrapComponents: bootWith({
					"federation-acme": { enabled: false },
					...coreConfigForTests({
						federations: {
							corp: enabledEntry("acme", "corp", { issuer: "https://corp.example" }),
						} as never,
					}),
				}),
			}),
		);

		expect(err.reason).toBe("federation-type-unhandled");
		expect(err.details).toMatchObject({ unhandled: [{ federationName: "corp", type: "acme" }] });
	});
});

describe("federationTypes — refused", () => {
	it("two packages claiming one type refuse boot at stage 1", async () => {
		const declaration = {
			entrySchema: AcmeEntry,
			factory: () => providerNamed("a"),
			redirectPolicy: () => policyFor("a"),
		};
		const first = defineModule({
			name: "federation-acme",
			contributes: { federationTypes: { acme: declaration } },
		});
		const second = defineModule({
			name: "federation-acme-too",
			contributes: { federationTypes: { acme: declaration } },
		});

		const err = await refusal(
			createApp({ modules: [first, second], bootstrapComponents: bootWith() }),
		);

		expect(err.reason).toBe("duplicate-contribute");
		expect(err.stage).toBe("validateManifests");
		expect(err.details).toMatchObject({
			kind: "federationTypes",
			identity: "acme",
			modules: ["federation-acme", "federation-acme-too"],
		});
	});

	it.each([
		["null", null],
		["without a factory", { entrySchema: AcmeEntry, redirectPolicy: () => policyFor("acme") }],
		["without a redirect policy", { entrySchema: AcmeEntry, factory: () => providerNamed("acme") }],
		[
			"without an entry schema",
			{ factory: () => providerNamed("acme"), redirectPolicy: () => policyFor("acme") },
		],
		[
			"with an entry schema that is not a schema",
			{
				entrySchema: {},
				factory: () => providerNamed("acme"),
				redirectPolicy: () => policyFor("acme"),
			},
		],
		["a bare function", () => providerNamed("acme")],
	])(
		"a declaration written in JavaScript %s is refused at stage 1 naming the module and type",
		async (_label, declaration) => {
			const acme = defineModule({
				name: "federation-acme",
				contributes: { federationTypes: { acme: declaration as never } },
			});

			const err = await refusal(createApp({ modules: [acme], bootstrapComponents: bootWith() }));

			expect(err.reason).toBe("contribution-malformed");
			expect(err.stage).toBe("validateManifests");
			expect(err.details).toMatchObject({
				reason: "contribution-malformed",
				module: "federation-acme",
				kind: "federationTypes",
				name: "acme",
				channel: "contributes",
			});
		},
	);

	it("a host may not replace the collector: the kind is guarded", async () => {
		const err = await refusal(
			createApp({
				modules: [],
				bootstrapComponents: bootWith(),
				contributionKinds: { federationTypes: mergeWithBuiltins(undefined).federationTypes },
			}),
		);

		expect(err.reason).toBe("contribution-kind-guarded");
		expect(err.details).toEqual({ reason: "contribution-kind-guarded", kind: "federationTypes" });
	});
});

describe("federationTypes — read once", () => {
	it("keeps the schema and factories it registered: a declaration changed after boot changes nothing", async () => {
		const original = vi.fn((_deps: unknown, instance: { name: string }) =>
			providerNamed(instance.name),
		);
		const originalPolicy = vi.fn((_deps: unknown, instance: { name: string }) =>
			policyFor(instance.name),
		);
		const declaration: {
			entrySchema: z.ZodType;
			factory: typeof original;
			redirectPolicy: typeof originalPolicy;
		} = { entrySchema: AcmeEntry, factory: original, redirectPolicy: originalPolicy };
		const acme = defineModule({
			name: "federation-acme",
			contributes: { federationTypes: { acme: declaration as never } },
		});

		const types = await registeredTypes([acme]);
		const replaced = vi.fn(() => providerNamed("replaced"));
		const replacedPolicy = vi.fn(() => policyFor("replaced"));
		declaration.factory = replaced as never;
		declaration.redirectPolicy = replacedPolicy as never;
		declaration.entrySchema = z.object({ other: z.string() });

		const registered = types?.get("acme");
		expect(registered?.entrySchema).toBe(AcmeEntry);
		const instance = { name: "corp", callbackURL: "https://cb", entry: { issuer: "https://corp" } };
		expect((await registered?.create(instance))?.name).toBe("corp");
		expect(await registered?.redirectPolicy(instance)).toMatchObject({ for: "corp" });
		expect(original).toHaveBeenCalledOnce();
		expect(originalPolicy).toHaveBeenCalledOnce();
		expect(replaced).not.toHaveBeenCalled();
		expect(replacedPolicy).not.toHaveBeenCalled();
	});
});

describe("federationTypes — the kind takes a record keyed by type", () => {
	it.each<readonly [string, "contributes" | "overrides", unknown]>([
		["an array", "contributes", [{ entrySchema: AcmeEntry, factory: () => providerNamed("a") }]],
		["a function", "contributes", () => providerNamed("a")],
		["null", "overrides", null],
	])("refuses %s in its place at stage 1", async (_label, channel, container) => {
		const mod = defineModule({
			name: "federation-container",
			[channel]: { federationTypes: container as never },
		});

		const err = await refusal(createApp({ modules: [mod], bootstrapComponents: bootWith() }));

		expect(err.reason).toBe("contribution-malformed");
		expect(err.stage).toBe("validateManifests");
		expect(err.details).toEqual({
			reason: "contribution-malformed",
			module: "federation-container",
			kind: "federationTypes",
			channel,
			problem: expect.stringContaining("record keyed by"),
		});
	});
});
