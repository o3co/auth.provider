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
 * registers the pair under the entry's name at stage 4. Every entry names
 * its type, and an enabled entry whose type no module registers refuses boot.
 */

import { describe, expect, it, vi } from "vitest";
import { z } from "zod";
import type { FederationProvider } from "../../federations/types.mjs";
import type { Module } from "../../modules/manifest/index.mjs";
import { defineModule } from "../../modules/manifest/index.mjs";
import { federationTypeForTests } from "../../testing/fixtures/federationType.mjs";
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

/** The four slots an enabled federation needs wired (`federation-stores-wiring`). */
const federationStores = defineModule({
	name: "test:federation-stores",
	provides: {
		userSessionStore: () => ({ kind: "stub" }),
		sessionLifecycle: () => ({ kind: "stub" }),
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
		requires: ["federationSettings"],
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

/** An enabled entry of `type` with a callback URL and `extra`. */
const enabledEntry = (type: string, name: string, extra: Record<string, unknown> = {}) => ({
	enabled: true,
	type,
	callbackURL: `https://auth.example/session/federation/${name}/callback`,
	...extra,
});

/**
 * Stages 1 to 3 over the built-in kinds, then stage 4 started: the kinds,
 * which can be read whether stage 4 refuses or not, and what it settles to.
 */
async function throughStage4(modules: readonly Module[], bootstrap: BootstrapMap) {
	const kinds = mergeWithBuiltins(undefined);
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
	return { kinds, applied: applyContributions(material, kinds) };
}

/** Stages 1 to 4 over the built-in kinds, answering the `federationTypes` collector. */
async function registeredTypes(modules: readonly Module[], extra: Record<string, unknown> = {}) {
	const { kinds, applied } = await throughStage4(modules, bootWith(extra));
	await applied;
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

/** The issues a `config-validation-failed` refusal lists. */
const issuesOf = (
	err: BootError,
): readonly { readonly path: unknown[]; readonly message: string }[] =>
	(err.details as unknown as { issues: { path: unknown[]; message: string }[] }).issues;

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
			expect.objectContaining({ federationSettings: expect.anything() }),
			instance,
		);
		expect(await registered?.redirectPolicy(instance)).toMatchObject({ for: "corp" });
		expect(redirectPolicy).toHaveBeenCalledWith(
			expect.objectContaining({ federationSettings: expect.anything() }),
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
					callbackMeetsFreshness: true,
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
		expect(factory).toHaveBeenCalledWith(
			expect.objectContaining({ federationSettings: expect.anything() }),
			{
				name: "corp",
				callbackURL: "https://auth.example/session/federation/corp/callback",
				entry: { issuer: "https://corp.example" },
			},
		);
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

	it("refuses an entry whose type's schema answers a value that throws as it is copied", async () => {
		const { module, factory } = acmePackage({
			entrySchema: z.object({ issuer: z.string() }).transform(() => ({
				get issuer(): string {
					throw new Error("issuer unreadable");
				},
			})),
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
		expect(err.stage).toBe("validateManifests");
		expect(err.details).toMatchObject({
			issues: [expect.objectContaining({ path: ["core", "federations", "corp"] })],
			modules: [{ module: "federation-acme", schemaPath: "core.federations.corp" }],
		});
		expect(err.message).toContain("core.federations.corp");
		expect(err.message).toContain("issuer unreadable");
		expect(factory).not.toHaveBeenCalled();
	});

	it("says a dispatched entry is flat when its keys are nested under its type", async () => {
		const { module, factory } = acmePackage();

		const err = await refusal(
			createApp({
				modules: [federationStores, module],
				bootstrapComponents: federationsConfig({
					corp: {
						enabled: true,
						type: "acme",
						acme: {
							callbackURL: "https://auth.example/session/federation/corp/callback",
							issuer: "https://corp.example",
						},
					},
				}),
			}),
		);

		expect(err.reason).toBe("config-validation-failed");
		expect(err.message).toContain("core.federations.corp.callbackURL");
		expect(err.message).toContain(
			'a dispatched entry is flat: the keys nested under "acme" are not read',
		);
		expect(factory).not.toHaveBeenCalled();
	});

	it("does not say an entry is flat when the key named after its type is not an object", async () => {
		const { module } = acmePackage({
			entrySchema: z.object({ issuer: z.string(), acme: z.string() }),
		});

		const err = await refusal(
			createApp({
				modules: [federationStores, module],
				bootstrapComponents: federationsConfig({
					corp: { enabled: true, type: "acme", issuer: "https://corp.example", acme: "x" },
				}),
			}),
		);

		expect(err.message).toContain("core.federations.corp.callbackURL");
		expect(err.message).not.toContain("flat");
	});

	it("says a dispatched entry is flat when its type's strict schema refuses the key named after its type", async () => {
		const { module, factory } = acmePackage({
			entrySchema: z.object({ issuer: z.string().optional() }).strict(),
		});

		const err = await refusal(
			createApp({
				modules: [federationStores, module],
				bootstrapComponents: federationsConfig({
					corp: enabledEntry("acme", "corp", {
						acme: { issuer: "https://corp.example" },
						extra: { issuer: "https://corp.example" },
					}),
				}),
			}),
		);

		expect(err.reason).toBe("config-validation-failed");
		const issues = issuesOf(err);
		expect(issues).toHaveLength(1);
		expect(issues[0]?.path).toEqual(["core", "federations", "corp"]);
		expect(issues[0]?.message).toContain(
			'a dispatched entry is flat: the keys nested under "acme" are not read, so write them beside its type',
		);
		expect(err.message).toContain(
			'a dispatched entry is flat: the keys nested under "acme" are not read',
		);
		expect(err.message).not.toContain("core.federations.corp.callbackURL");
		expect(factory).not.toHaveBeenCalled();
	});

	it("does not say an entry is flat when a strict schema refuses another key", async () => {
		const { module } = acmePackage({ entrySchema: z.object({ issuer: z.string() }).strict() });

		const err = await refusal(
			createApp({
				modules: [federationStores, module],
				bootstrapComponents: federationsConfig({
					corp: enabledEntry("acme", "corp", {
						issuer: "https://corp.example",
						other: { issuer: "https://corp.example" },
					}),
				}),
			}),
		);

		expect(err.reason).toBe("config-validation-failed");
		expect(err.message).not.toContain("flat");
	});

	it("boots a nested shape under a type whose schema reads the key named after it", async () => {
		const handle = await createApp({
			modules: [federationStores, federationTypeForTests("acme")],
			bootstrapComponents: federationsConfig({
				corp: enabledEntry("acme", "corp", { acme: { issuer: "https://corp.example" } }),
			}),
		});

		expect(handle.components.federationProviders?.get("corp")?.name).toBe("corp");
		await handle.dispose();
	});

	it("refuses two enabled entries that share a callbackURL, naming the other entry and not the URL", async () => {
		const { module, factory } = acmePackage();
		const shared = "https://auth.example/session/federation/shared/callback";

		const err = await refusal(
			createApp({
				modules: [federationStores, module],
				bootstrapComponents: federationsConfig({
					corp: enabledEntry("acme", "corp", {
						issuer: "https://corp.example",
						callbackURL: shared,
					}),
					partner: enabledEntry("acme", "partner", {
						issuer: "https://partner.example",
						callbackURL: shared,
					}),
					"third idp": enabledEntry("acme", "third", {
						issuer: "https://third.example",
						callbackURL: shared,
					}),
				}),
			}),
		);

		expect(err.reason).toBe("config-validation-failed");
		expect(err.stage).toBe("validateManifests");
		expect(err.details).toMatchObject({
			reason: "config-validation-failed",
			issues: [
				expect.objectContaining({ path: ["core", "federations", "partner", "callbackURL"] }),
				expect.objectContaining({ path: ["core", "federations", "third idp"] }),
				expect.objectContaining({ path: ["core", "federations", "third idp", "callbackURL"] }),
			],
		});
		const issues = issuesOf(err);
		expect(issues[0]?.message).toContain("core.federations.corp");
		expect(issues[2]?.message).toContain("core.federations.corp");
		expect(err.message).toContain("core.federations.partner.callbackURL");
		expect(err.message).toContain('core.federations."third idp".callbackURL');
		expect(err.message).not.toContain(shared);
		expect(JSON.stringify(err.details)).not.toContain(shared);
		expect(factory).not.toHaveBeenCalled();
	});

	it("names an entry that is not a bare key quoted when another entry shares its callbackURL", async () => {
		const { module } = acmePackage();
		const shared = "https://auth.example/cb";

		const err = await refusal(
			createApp({
				modules: [federationStores, module],
				bootstrapComponents: federationsConfig({
					"corp.idp": enabledEntry("acme", "corp", { issuer: "https://a", callbackURL: shared }),
					partner: enabledEntry("acme", "partner", { issuer: "https://b", callbackURL: shared }),
				}),
			}),
		);

		const issues = issuesOf(err);
		expect(issues.at(-1)?.path).toEqual(["core", "federations", "partner", "callbackURL"]);
		expect(issues.at(-1)?.message).toContain('core.federations."corp.idp"');
	});

	it("boots two entries sharing a callbackURL when one of them is disabled", async () => {
		const { module } = acmePackage();
		const shared = "https://auth.example/session/federation/corp/callback";

		const handle = await createApp({
			modules: [federationStores, module],
			bootstrapComponents: federationsConfig({
				corp: enabledEntry("acme", "corp", { issuer: "https://corp.example" }),
				partner: {
					...enabledEntry("acme", "partner", { issuer: "https://partner.example" }),
					enabled: false,
					callbackURL: shared,
				},
			}),
		});

		expect([...(handle.components.federationProviders?.keys() ?? [])]).toEqual(["corp"]);
		await handle.dispose();
	});

	it("boots two enabled entries whose callbackURLs differ", async () => {
		const { module } = acmePackage();

		const handle = await createApp({
			modules: [federationStores, module],
			bootstrapComponents: federationsConfig({
				corp: enabledEntry("acme", "corp", { issuer: "https://corp.example" }),
				partner: enabledEntry("acme", "partner", { issuer: "https://partner.example" }),
			}),
		});

		expect([...(handle.components.federationProviders?.keys() ?? [])]).toEqual(["corp", "partner"]);
		await handle.dispose();
	});

	it("writes a name that is not a bare key quoted, so a newline in it does not split the message", async () => {
		const { module } = acmePackage();

		const err = await refusal(
			createApp({
				modules: [federationStores, module],
				bootstrapComponents: federationsConfig({
					"corp\nidp": enabledEntry("acme", "corp", { issuer: 42 }),
				}),
			}),
		);

		expect(err.reason).toBe("config-validation-failed");
		expect(err.message).not.toContain("\n");
		expect(err.message).toContain('core.federations."corp\\nidp": ');
		expect(err.message).toContain('core.federations."corp\\nidp".issuer');
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
			// Stage by stage, so what was registered can be read after the refusal.
			const { kinds, applied } = await throughStage4(
				[closing, federationStores, module],
				federationsConfig({
					corp: enabledEntry("acme", "corp", { issuer: "https://corp.example" }),
				}),
			);

			const err = await refusal(applied);

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
			expect([...(kinds.federations?.entries() ?? [])]).toEqual([]);
			expect([...(kinds.federationRedirectPolicies?.entries() ?? [])]).toEqual([]);
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
	it("lists every enabled entry whose type no installed module registers, with the types handled", async () => {
		const err = await refusal(
			createApp({
				modules: [federationStores, acmePackage().module],
				bootstrapComponents: federationsConfig({
					corp: enabledEntry("acme", "corp", { issuer: "https://corp.example" }),
					partner: enabledEntry("acmee", "partner", { clientSecret: "s3cr3t-value" }),
					legacy: enabledEntry("nobody", "legacy", { clientSecret: "s3cr3t-value" }),
					off: { enabled: false, type: "nobody" },
				}),
			}),
		);

		expect(err.reason).toBe("federation-type-unhandled");
		expect(err.stage).toBe("validateManifests");
		expect(err.details).toEqual({
			reason: "federation-type-unhandled",
			unhandled: [
				{ federationName: "partner", type: "acmee" },
				{ federationName: "legacy", type: "nobody" },
			],
			handled: ["acme"],
		});
		expect(err.message).toContain("core.federations.partner");
		expect(err.message).toContain('"acmee"');
		expect(err.message).toContain('federationTypes["acmee"]');
		expect(err.message).toContain("core.federations.legacy");
		expect(err.message).toContain('federationTypes["nobody"]');
		expect(err.message).toContain('["acme"]');
		expect(err.message).toContain("enabled = false");
		expect(err.message).not.toContain("s3cr3t-value");
	});

	it.each([
		["an enabled entry", true],
		["a disabled entry", false],
	])("refuses %s without a type at core.federations.<name>.type", async (_label, enabled) => {
		const err = await refusal(
			createApp({
				modules: [federationStores],
				bootstrapComponents: federationsConfig({
					google: {
						enabled,
						callbackURL: "https://auth.example/session/federation/google/callback",
					},
				}),
			}),
		);

		expect(err.reason).toBe("config-validation-failed");
		expect(err.stage).toBe("validateManifests");
		expect(err.message).toContain("core.federations.google.type");
		expect(err.details).toMatchObject({
			reason: "config-validation-failed",
			issues: expect.arrayContaining([
				expect.objectContaining({ path: ["core", "federations", "google", "type"] }),
			]),
		});
	});

	it("writes a name that is not a bare key quoted in the row's refusal, so a newline does not split it", async () => {
		const unhandled = await refusal(
			createApp({
				modules: [federationStores],
				bootstrapComponents: federationsConfig({
					"corp\nidp": enabledEntry("nobody", "corp"),
					"partner\nidp": enabledEntry("nobody", "partner"),
				}),
			}),
		);
		expect(unhandled.reason).toBe("federation-type-unhandled");
		expect(unhandled.message).not.toContain("\n");
		expect(unhandled.message).toContain('core.federations."corp\\nidp" names the type "nobody"');
		expect(unhandled.message).toContain('core.federations."partner\\nidp".enabled = false');
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

describe("core.federations — the dispatched entries are read once they register", () => {
	const corp = federationsConfig({
		corp: enabledEntry("acme", "corp", { issuer: "https://corp.example" }),
	});

	it.each(["federationProviders", "federationRedirectPolicyResolver"])(
		"refuses a name-keyed contribution factory that reads %s before the dispatched entries register",
		async (key) => {
			const reader = defineModule({
				name: "test:early-reader",
				requires: [key] as never,
				contributes: {
					grants: {
						"urn:test:early": ((deps: Record<string, ReadonlyMap<string, unknown>>) => {
							deps[key]?.get("corp");
							return { handle: async () => ({}) };
						}) as never,
					},
				},
			});

			const err = await refusal(
				createApp({
					modules: [federationStores, acmePackage().module, reader],
					bootstrapComponents: corp,
				}),
			);

			expect(err.reason).toBe("contribute-factory-failed");
			expect(err.details).toMatchObject({
				module: "test:early-reader",
				kind: "grants",
				name: "urn:test:early",
			});
			expect(err.message).toContain(`${key} was read before every federation was registered`);
		},
	);

	it("refuses a type's factory that reads the providers while the dispatched entries register", async () => {
		const reading = defineModule({
			name: "federation-acme",
			requires: ["federationProviders"] as never,
			contributes: {
				federationTypes: {
					acme: {
						entrySchema: AcmeEntry,
						factory: ((
							deps: Record<string, ReadonlyMap<string, unknown>>,
							instance: { name: string },
						) => {
							deps.federationProviders?.get("partner");
							return providerNamed(instance.name);
						}) as never,
						redirectPolicy: (() => policyFor("corp")) as never,
					},
				},
			},
		});

		const err = await refusal(
			createApp({ modules: [federationStores, reading], bootstrapComponents: corp }),
		);

		expect(err.reason).toBe("contribute-factory-failed");
		expect(err.details).toMatchObject({
			module: "federation-acme",
			kind: "federations",
			name: "corp",
		});
		expect(err.message).toContain(
			"federationProviders was read before every federation was registered",
		);
	});

	it("hands a routes factory both projections with every dispatched entry registered", async () => {
		const seen: unknown[] = [];
		const reader = defineModule({
			name: "test:route-reader",
			requires: ["federationProviders", "federationRedirectPolicyResolver"] as never,
			contributes: {
				routes: [
					((deps: Record<string, ReadonlyMap<string, unknown>>) => {
						seen.push(
							[...(deps.federationProviders?.keys() ?? [])],
							[...(deps.federationRedirectPolicyResolver?.keys() ?? [])],
						);
						return {
							id: "test-route-reader",
							mountPath: "/__test_route_reader__",
							handler: (_req: unknown, _res: unknown, next: () => void) => next(),
						};
					}) as never,
				],
			},
		});

		const handle = await createApp({
			modules: [federationStores, acmePackage().module, reader],
			bootstrapComponents: corp,
		});

		expect(seen).toEqual([["corp"], ["corp"]]);
		await handle.dispose();
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
