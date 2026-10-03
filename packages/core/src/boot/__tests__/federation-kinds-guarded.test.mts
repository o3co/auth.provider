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
 * `federations` and `federationRedirectPolicies` are core's: boot registers
 * a federation's provider and redirect policy from its `core.federations`
 * entry, with the factories of the type the entry names under
 * `federationTypes`, and from nothing else. A module's contribution or
 * override of either kind, and a host collector for either, refuse boot at
 * stage 1 (`contribution-kind-guarded`) before any factory runs.
 */

import { describe, expect, it, vi } from "vitest";
import { z } from "zod";
import type { FederationProvider } from "../../federations/types.mjs";
import { defineModule } from "../../modules/manifest/index.mjs";
import { coreConfigForTests, makeValidCoreConfig } from "../../testing/fixtures/valid-config.mjs";
import { createApp, mergeWithBuiltins } from "../create-app.mjs";
import type { BootstrapMap } from "../types.mjs";
import { BootError } from "../types.mjs";

const KINDS = ["federations", "federationRedirectPolicies"] as const;
const CHANNELS = ["contributes", "overrides"] as const;

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

const policyFor = (name: string) => ({
	for: name,
	validateRedirect: () => ({ ok: true as const, value: undefined }),
	resolveCallbackRedirect: () => ({ ok: true as const, value: "https://app.example" }),
});

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

/** A federation package handling the type `acme`, with a spy on its provider factory. */
function acmePackage() {
	const factory = vi.fn((_deps: unknown, instance: { name: string }) =>
		providerNamed(instance.name),
	);
	const module = defineModule({
		name: "federation-acme",
		contributes: {
			federationTypes: {
				acme: {
					entrySchema: z.object({ issuer: z.string() }),
					factory: factory as never,
					redirectPolicy: ((_deps: unknown, instance: { name: string }) =>
						policyFor(instance.name)) as never,
				},
			},
		},
	});
	return { module, factory };
}

/** A configuration with one enabled entry, `corp`, of the type `acme`. */
const corp = bootWith(
	coreConfigForTests({
		federations: {
			corp: {
				enabled: true,
				type: "acme",
				callbackURL: "https://auth.example/session/federation/corp/callback",
				issuer: "https://corp.example",
			},
		} as never,
	}),
);

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

describe("federations and federationRedirectPolicies — a module may neither contribute nor override them", () => {
	for (const kind of KINDS) {
		for (const channel of CHANNELS) {
			it(`refuses ${channel}.${kind} at stage 1, before any factory runs`, async () => {
				const value = vi.fn(() =>
					kind === "federations" ? providerNamed("corp") : policyFor("corp"),
				);
				const { module, factory } = acmePackage();
				const direct = defineModule({
					name: "test:direct",
					[channel]: { [kind]: { corp: value } },
				} as never);

				const err = await refusal(
					createApp({ modules: [federationStores, module, direct], bootstrapComponents: corp }),
				);

				expect(err.reason).toBe("contribution-kind-guarded");
				expect(err.stage).toBe("validateManifests");
				expect(err.details).toEqual({
					reason: "contribution-kind-guarded",
					kind,
					channel,
					module: "test:direct",
					name: "corp",
				});
				expect(err.message).toContain('Module "test:direct"');
				expect(err.message).toContain(`${channel} ${kind} "corp"`);
				expect(err.message).toContain("register a type under federationTypes");
				expect(value).not.toHaveBeenCalled();
				expect(factory).not.toHaveBeenCalled();
			});
		}
	}

	it.each(KINDS)("refuses %s contributed as a list, naming no entry", async (kind) => {
		const direct = defineModule({
			name: "test:direct",
			contributes: { [kind]: [() => providerNamed("corp")] },
		} as never);

		const err = await refusal(createApp({ modules: [direct], bootstrapComponents: bootWith() }));

		expect(err.reason).toBe("contribution-kind-guarded");
		expect(err.details).toEqual({
			reason: "contribution-kind-guarded",
			kind,
			channel: "contributes",
			module: "test:direct",
		});
	});

	it("refuses a module that contributes the kind with no federation configured", async () => {
		const direct = defineModule({
			name: "test:direct",
			contributes: { federations: { google: () => providerNamed("google") } },
		} as never);

		const err = await refusal(createApp({ modules: [direct], bootstrapComponents: bootWith() }));

		expect(err.reason).toBe("contribution-kind-guarded");
		expect(err.details).toMatchObject({ kind: "federations", name: "google" });
	});
});

describe("federations and federationRedirectPolicies — a host may not supply the collector", () => {
	it.each(KINDS)("refuses contributionKinds.%s before anything is merged", async (kind) => {
		const collector = mergeWithBuiltins(undefined)[kind];

		const err = await refusal(
			createApp({
				modules: [],
				bootstrapComponents: bootWith(),
				contributionKinds: { [kind]: collector },
			}),
		);

		expect(err.reason).toBe("contribution-kind-guarded");
		expect(err.stage).toBe("validateManifests");
		expect(err.details).toEqual({ reason: "contribution-kind-guarded", kind });
		expect(err.message).toContain(`contributionKinds replaces the collector for "${kind}"`);
		expect(err.message).toContain("federationTypes");
	});
});

describe("federations and federationRedirectPolicies — registered from the dispatched entries", () => {
	it("registers each enabled entry's provider and redirect policy under its name", async () => {
		const handle = await createApp({
			modules: [federationStores, acmePackage().module],
			bootstrapComponents: corp,
		});

		const components = handle.components as Record<string, ReadonlyMap<string, unknown>>;
		expect([...(components.federationProviders?.keys() ?? [])]).toEqual(["corp"]);
		expect(components.federationRedirectPolicyResolver?.get("corp")).toMatchObject({
			for: "corp",
		});
	});
});
