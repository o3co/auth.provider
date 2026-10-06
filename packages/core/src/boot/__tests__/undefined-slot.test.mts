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
 * A component slot holding `undefined` is unfilled, whichever source put it
 * there: a `bootstrapComponents` or `overrideComponents` entry given as
 * `undefined`, or a provider resolving to it. A module requiring the slot is
 * refused (`missing-required-component`) before its factory runs, and an
 * enabled federation refuses a store slot holding it
 * (`federation-stores-incomplete`). An override given as `undefined` still
 * replaces the slot's provider, as any override does.
 */
import { describe, expect, it } from "vitest";
import { createApp, defineModule, type Module } from "../../index.mjs";
import { federationTypeForTests } from "../../testing/fixtures/federationType.mjs";
import { coreConfigForTests, makeValidAppConfig } from "../../testing/fixtures/valid-config.mjs";
import { BootError } from "../types.mjs";

const KEY = "undefinedSlotFixture";

const boot = (extra: Record<string, unknown> = {}) =>
	({
		config: { ...makeValidAppConfig(), ...coreConfigForTests() },
		pathResolver: (p: string) => p,
		...extra,
	}) as never;

/**
 * A module boot activates (its contribution makes it a root) that reads
 * `key` as `requires` or `optional`; `handed` keeps what its deps held, and
 * `ran` whether its factory ran.
 */
function reader(name: string, key: string, as: "requires" | "optional") {
	const seen: { ran: boolean; value?: unknown } = { ran: false };
	const module = defineModule({
		name,
		[as]: [key],
		contributes: {
			grantMiddleware: [
				(deps: Record<string, unknown>) => {
					seen.ran = true;
					seen.value = deps[key];
					return null;
				},
			],
		},
	} as never);
	return { module, seen };
}

/** A module providing `key` with `value`, counting its runs and cleanups. */
function provider(key: string, value: unknown) {
	const seen = { runs: 0, cleanups: 0 };
	const module = defineModule({
		name: `test:${key}-provider`,
		provides: {
			[key]: async () => {
				seen.runs++;
				return value;
			},
		},
		lifecycle: { [key]: { cleanup: () => void seen.cleanups++ } },
	} as never);
	return { module, seen };
}

const refusedAsMissing = (module: string, key = KEY) => ({
	reason: "missing-required-component",
	stage: "materializeComponents",
	details: { reason: "missing-required-component", missingKey: key, rootModule: module },
});

describe("a required slot holding undefined", () => {
	it("refuses an override given as undefined, before the reader runs", async () => {
		const r = reader("test:requiring", KEY, "requires");
		const err = await createApp({
			modules: [r.module],
			bootstrapComponents: boot(),
			overrideComponents: { [KEY]: undefined } as never,
		}).catch((e: unknown) => e);
		expect(err).toBeInstanceOf(BootError);
		expect(err).toMatchObject(refusedAsMissing("test:requiring"));
		expect((err as BootError).message).toContain(KEY);
		expect(r.seen.ran).toBe(false);
	});

	it("refuses a bootstrapComponents entry given as undefined", async () => {
		const r = reader("test:requiring", KEY, "requires");
		await expect(
			createApp({ modules: [r.module], bootstrapComponents: boot({ [KEY]: undefined }) }),
		).rejects.toMatchObject(refusedAsMissing("test:requiring"));
		expect(r.seen.ran).toBe(false);
	});

	it("refuses a provider resolving undefined, after cleaning up what it materialised", async () => {
		const r = reader("test:requiring", KEY, "requires");
		const p = provider(KEY, undefined);
		await expect(
			createApp({ modules: [r.module, p.module], bootstrapComponents: boot() }),
		).rejects.toMatchObject(refusedAsMissing("test:requiring"));
		expect(r.seen.ran).toBe(false);
		expect(p.seen.cleanups).toBe(1);
	});

	it("refuses before a provider requiring the slot runs", async () => {
		const p = provider(KEY, undefined);
		const downstream = { runs: 0 };
		const requiringProvider = defineModule({
			name: "test:requiring-provider",
			requires: [KEY],
			provides: {
				dependentFixture: () => {
					downstream.runs++;
					return { kind: "stub" };
				},
			},
		} as never);
		const r = reader("test:dependent-reader", "dependentFixture", "requires");
		await expect(
			createApp({
				modules: [p.module, requiringProvider, r.module],
				bootstrapComponents: boot(),
			}),
		).rejects.toMatchObject(refusedAsMissing("test:requiring-provider"));
		expect(downstream.runs).toBe(0);
		expect(p.seen.cleanups).toBe(1);
	});

	it("hands a real value through, from an override, a bootstrap entry or a provider", async () => {
		const value = { kind: "stub" };
		const boots = [
			(m: Module) =>
				createApp({
					modules: [m],
					bootstrapComponents: boot(),
					overrideComponents: { [KEY]: value } as never,
				}),
			(m: Module) => createApp({ modules: [m], bootstrapComponents: boot({ [KEY]: value }) }),
			(m: Module) =>
				createApp({ modules: [m, provider(KEY, value).module], bootstrapComponents: boot() }),
		];
		for (const bootWith of boots) {
			const r = reader("test:requiring", KEY, "requires");
			const handle = await bootWith(r.module);
			expect(r.seen.value).toBe(value);
			await handle.dispose();
		}
	});

	it("leaves an optional slot without an absence policy holding undefined as absent", async () => {
		const r = reader("test:optional", KEY, "optional");
		const handle = await createApp({
			modules: [r.module],
			bootstrapComponents: boot(),
			overrideComponents: { [KEY]: undefined } as never,
		});
		expect(r.seen.ran).toBe(true);
		expect(r.seen.value).toBeUndefined();
		await handle.dispose();
	});
});

describe("an override given as undefined over a module providing the slot", () => {
	it("replaces the provider, which does not run, so an optional reader reads it absent", async () => {
		const r = reader("test:optional", KEY, "optional");
		const p = provider(KEY, { kind: "provided" });
		const handle = await createApp({
			modules: [r.module, p.module],
			bootstrapComponents: boot(),
			overrideComponents: { [KEY]: undefined } as never,
		});
		expect(p.seen.runs).toBe(0);
		expect(r.seen.value).toBeUndefined();
		await handle.dispose();
	});

	it("refuses a module requiring the slot", async () => {
		const r = reader("test:requiring", KEY, "requires");
		const p = provider(KEY, { kind: "provided" });
		await expect(
			createApp({
				modules: [r.module, p.module],
				bootstrapComponents: boot(),
				overrideComponents: { [KEY]: undefined } as never,
			}),
		).rejects.toMatchObject(refusedAsMissing("test:requiring"));
		expect(p.seen.runs).toBe(0);
		expect(r.seen.ran).toBe(false);
	});

	it("still replaces the provider with a real value", async () => {
		const value = { kind: "override" };
		const r = reader("test:requiring", KEY, "requires");
		const p = provider(KEY, { kind: "provided" });
		const handle = await createApp({
			modules: [r.module, p.module],
			bootstrapComponents: boot(),
			overrideComponents: { [KEY]: value } as never,
		});
		expect(p.seen.runs).toBe(0);
		expect(r.seen.value).toBe(value);
		await handle.dispose();
	});
});

const FEDERATION_STORES = [
	"userSessionStore",
	"sessionLifecycle",
	"federationTokenStore",
	"refreshTokenFamilyRevocation",
] as const;

describe("an enabled federation's store slot holding undefined", () => {
	const federationBoot = () =>
		({
			config: {
				...makeValidAppConfig(),
				...coreConfigForTests({
					declaredAbsent: ["auditSink"],
					federations: {
						google: {
							enabled: true,
							type: "google",
							callbackURL: "https://auth.example/session/federation/google/callback",
						},
					},
				}),
			},
			pathResolver: (p: string) => p,
		}) as never;
	const google = federationTypeForTests("google");
	const stores = (overrides: Record<string, unknown> = {}) => ({
		...Object.fromEntries(FEDERATION_STORES.map((key) => [key, { kind: "stub" }])),
		...overrides,
	});

	it("refuses one given as undefined", async () => {
		const err = await createApp({
			modules: [google],
			bootstrapComponents: federationBoot(),
			overrideComponents: stores({ federationTokenStore: undefined }) as never,
		}).catch((e: unknown) => e);
		expect(err).toBeInstanceOf(BootError);
		expect(err).toMatchObject({
			reason: "federation-stores-incomplete",
			stage: "materializeComponents",
			details: {
				reason: "federation-stores-incomplete",
				federationName: "google",
				missing: ["federationTokenStore"],
			},
		});
	});

	it("refuses one from a provider resolving undefined", async () => {
		const { federationTokenStore: _, ...rest } = stores();
		const r = reader("test:store-reader", "federationTokenStore", "optional");
		await expect(
			createApp({
				modules: [google, r.module, provider("federationTokenStore", undefined).module],
				bootstrapComponents: federationBoot(),
				overrideComponents: rest as never,
			}),
		).rejects.toMatchObject({
			reason: "federation-stores-incomplete",
			details: { missing: ["federationTokenStore"] },
		});
		expect(r.seen.ran).toBe(false);
	});

	it("boots with every store holding a value", async () => {
		const handle = await createApp({
			modules: [google],
			bootstrapComponents: federationBoot(),
			overrideComponents: stores() as never,
		});
		await handle.dispose();
	});
});
