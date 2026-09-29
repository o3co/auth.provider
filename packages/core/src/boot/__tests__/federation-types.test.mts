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
 * The `federationTypes` contribution kind: a federation package
 * declares, keyed by the `type` an entry of the `federations` configuration
 * names, the schema of such an entry and the factory that builds a provider
 * from one entry and its name. Registered by type, so two packages claiming
 * one type refuse boot; not dispatched yet — no entry is parsed and no
 * factory runs until the federations section moves under core.
 */

import { describe, expect, it, vi } from "vitest";
import { z } from "zod";
import type { FederationProvider } from "../../federations/types.mjs";
import type { Module } from "../../modules/manifest/index.mjs";
import { defineModule } from "../../modules/manifest/index.mjs";
import { makeValidCoreConfig } from "../../testing/fixtures/valid-config.mjs";
import { applyContributions } from "../apply-contributions.mjs";
import { createApp, mergeWithBuiltins } from "../create-app.mjs";
import { materializeComponents } from "../materialize-components.mjs";
import { planBoot } from "../plan-boot.mjs";
import type { BootstrapMap } from "../types.mjs";
import { BootError } from "../types.mjs";
import { validateManifests } from "../validate-manifests.mjs";

const bootWith = (extra: Record<string, unknown> = {}): BootstrapMap =>
	({
		config: { ...makeValidCoreConfig(), ...extra } as never,
		pathResolver: (s: string) => s,
	}) satisfies Record<string, unknown> as BootstrapMap;

const providerNamed = (name: string): FederationProvider => ({
	name,
	scope: ["openid"],
	buildAuthorizationUrl: () => new URL(`https://${name}.example/authorize`),
	exchangeCode: async () => ({ issuer: `https://${name}.example`, sub: "1", expiresAt: null }),
});

const AcmeEntry = z.object({ issuer: z.string() });

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

describe("federationTypes — declared by type", () => {
	it("registers each declaration under its type, its schema kept and its factory bound to the module's deps", async () => {
		const factory = vi.fn((_deps: unknown, instance: { name: string }) =>
			providerNamed(instance.name),
		);
		const acme = defineModule({
			name: "federation-acme",
			requires: ["config"],
			contributes: { federationTypes: { acme: { entrySchema: AcmeEntry, factory } } },
		});

		const types = await registeredTypes([acme]);

		const registered = types?.get("acme");
		expect(registered?.entrySchema).toBe(AcmeEntry);
		expect([...(types?.entries() ?? [])].map(([type]) => type)).toEqual(["acme"]);
		// Not dispatched: nothing has asked for a provider yet.
		expect(factory).not.toHaveBeenCalled();
		// When dispatch asks, the factory gets the module's deps and the entry with its name.
		const provider = await registered?.create({ name: "corp", entry: { issuer: "https://corp" } });
		expect(provider?.name).toBe("corp");
		expect(factory).toHaveBeenCalledWith(expect.objectContaining({ config: expect.anything() }), {
			name: "corp",
			entry: { issuer: "https://corp" },
		});
	});

	it("is not dispatched: a configured entry of the type is neither parsed nor built into a provider", async () => {
		const entrySchema = z.object({ issuer: z.string() });
		const parse = vi.spyOn(entrySchema, "parse");
		const safeParse = vi.spyOn(entrySchema, "safeParse");
		const factory = vi.fn(() => providerNamed("corp"));
		const acme = defineModule({
			name: "federation-acme",
			contributes: { federationTypes: { acme: { entrySchema, factory } } },
		});

		const handle = await createApp({
			modules: [acme],
			bootstrapComponents: bootWith({
				federations: { corp: { enabled: false, type: "acme", issuer: 42 } },
			}),
		});

		expect(parse).not.toHaveBeenCalled();
		expect(safeParse).not.toHaveBeenCalled();
		expect(factory).not.toHaveBeenCalled();
		expect(handle.components.federationProviders?.get("corp")).toBeUndefined();
		await handle.dispose();
	});

	it("an override replaces a type's declaration", async () => {
		const replacement = z.object({ issuer: z.string(), tenant: z.string() });
		const acme = defineModule({
			name: "federation-acme",
			contributes: {
				federationTypes: {
					acme: { entrySchema: AcmeEntry, factory: () => providerNamed("acme") },
				},
			},
		});
		const replacer = defineModule({
			name: "federation-acme-replacement",
			overrides: {
				federationTypes: {
					acme: { entrySchema: replacement, factory: () => providerNamed("acme") },
				},
			},
		});

		const types = await registeredTypes([acme, replacer]);

		expect(types?.get("acme")?.entrySchema).toBe(replacement);
	});
});

describe("federationTypes — refused", () => {
	it("two packages claiming one type refuse boot at stage 1", async () => {
		const first = defineModule({
			name: "federation-acme",
			contributes: {
				federationTypes: { acme: { entrySchema: AcmeEntry, factory: () => providerNamed("a") } },
			},
		});
		const second = defineModule({
			name: "federation-acme-too",
			contributes: {
				federationTypes: { acme: { entrySchema: AcmeEntry, factory: () => providerNamed("b") } },
			},
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
		["without a factory", { entrySchema: AcmeEntry }],
		["without an entry schema", { factory: () => providerNamed("acme") }],
		[
			"with an entry schema that is not a schema",
			{ entrySchema: {}, factory: () => providerNamed("acme") },
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
	it("keeps the schema and factory it registered: a declaration changed after boot changes nothing", async () => {
		const original = vi.fn((_deps: unknown, instance: { name: string }) =>
			providerNamed(instance.name),
		);
		const declaration: { entrySchema: z.ZodType; factory: typeof original } = {
			entrySchema: AcmeEntry,
			factory: original,
		};
		const acme = defineModule({
			name: "federation-acme",
			contributes: { federationTypes: { acme: declaration } },
		});

		const types = await registeredTypes([acme]);
		const replaced = vi.fn(() => providerNamed("replaced"));
		declaration.factory = replaced as never;
		declaration.entrySchema = z.object({ other: z.string() });

		const registered = types?.get("acme");
		expect(registered?.entrySchema).toBe(AcmeEntry);
		const provider = await registered?.create({ name: "corp", entry: { issuer: "https://corp" } });
		expect(provider?.name).toBe("corp");
		expect(original).toHaveBeenCalledOnce();
		expect(replaced).not.toHaveBeenCalled();
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
