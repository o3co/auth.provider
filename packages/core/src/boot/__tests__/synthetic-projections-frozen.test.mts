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
 * Every value boot builds itself and hands to modules under a synthetic
 * `ComponentMap` key (`SYNTHETIC_COMPONENT_KEYS`) is frozen where boot
 * injects it, all the way down through plain objects and arrays, before any
 * module receives it. Several modules read one projection, so one that
 * changed it would change what the others read: a write throws (`TypeError`,
 * modules being strict-mode code) and every other reader keeps the original.
 * Values a module or the host provides are not frozen here.
 */

import { describe, expect, it } from "vitest";
import { defineModule, type Module } from "../../modules/manifest/index.mjs";
import { SYNTHETIC_COMPONENT_KEYS } from "../../modules/manifest/synthetic-keys.mjs";
import { runReadinessProbes } from "../../readiness/run.mjs";
import { makeValidCoreConfig } from "../../testing/fixtures/valid-config.mjs";
import { unfrozenPath } from "../../testing/slots/shared.mjs";
import { applyContributions, freezeSyntheticSlots } from "../apply-contributions.mjs";
import { createApp, mergeWithBuiltins } from "../create-app.mjs";
import { materializeComponents } from "../materialize-components.mjs";
import { planBoot } from "../plan-boot.mjs";
import type { BootstrapMap } from "../types.mjs";
import { validateManifests } from "../validate-manifests.mjs";

declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly "test.projectionMutator": object;
		readonly "test.projectionReader": object;
		readonly "test.registrarUser": object;
	}
}

const SYNTHETIC_KEYS = [...SYNTHETIC_COMPONENT_KEYS];

const bootstrap = (): BootstrapMap =>
	({
		config: {
			...makeValidCoreConfig(),
			core: {
				...makeValidCoreConfig().core,
				outbound: { allowedHosts: ["api.example.com"] },
			},
		} as never,
		pathResolver: (s: string) => s,
	}) satisfies Record<string, unknown> as BootstrapMap;

/** The ways a module could change an object it was handed. */
const WRITES: Readonly<Record<string, (target: object, member: PropertyKey) => void>> = {
	assign: (target, member) => {
		(target as Record<PropertyKey, unknown>)[member] = "tampered";
	},
	add: (target) => {
		(target as Record<string, unknown>).tampered = true;
	},
	delete: (target, member) => {
		delete (target as Record<PropertyKey, unknown>)[member];
	},
	define: (target) => {
		Object.defineProperty(target, "tampered", { value: true });
	},
};

/** The writes in `WRITES` that change a member the object already holds. */
const MEMBER_WRITES: ReadonlySet<string> = new Set(["assign", "delete"]);

/** The first own member of `target` holding a plain object or an array, if any. */
function nestedObjectOf(target: object): object | undefined {
	for (const key of Reflect.ownKeys(target)) {
		const descriptor = Object.getOwnPropertyDescriptor(target, key);
		const value: unknown = descriptor?.value;
		if (typeof value === "object" && value !== null) return value;
	}
	return undefined;
}

/**
 * The members of `target` that differ from `before` — added, removed, or
 * holding another value or flag — compared with `Object.is`. (`toEqual`
 * cannot compare descriptor maps of a view that has `[Symbol.iterator]` and
 * `size` members: it reads the map as an iterable.)
 */
function changedMembers(target: object, before: PropertyDescriptorMap): string[] {
	const now: PropertyDescriptorMap = Object.getOwnPropertyDescriptors(target);
	const keys = new Set([...Reflect.ownKeys(now), ...Reflect.ownKeys(before)]);
	const fields = ["value", "get", "set", "writable", "enumerable", "configurable"] as const;
	return [...keys]
		.filter((key) => {
			const a = now[key as string];
			const b = before[key as string];
			return (
				a === undefined || b === undefined || fields.some((field) => !Object.is(a[field], b[field]))
			);
		})
		.map(String);
}

describe("synthetic projections are frozen where boot injects them", () => {
	it("holds every synthetic slot's value frozen all the way down once boot has finished", async () => {
		const handle = await createApp({ modules: [], bootstrapComponents: bootstrap() });
		try {
			const components = handle.components as Readonly<Record<string, unknown>>;
			for (const key of SYNTHETIC_KEYS) {
				expect(Object.hasOwn(components, key), key).toBe(true);
				expect(unfrozenPath(components[key], key)).toBeUndefined();
			}
		} finally {
			await handle.dispose();
		}
	});

	it("refuses a module's write to each projection with a TypeError, and another module keeps the original", async () => {
		const refused: Record<string, string> = {};
		const before = new Map<string, PropertyDescriptorMap>();
		const nestedBefore = new Map<string, PropertyDescriptorMap>();
		const mutator: Module = defineModule({
			name: "test:projection-mutator",
			requires: SYNTHETIC_KEYS as never,
			provides: {
				"test.projectionMutator": (deps: Record<string, unknown>) => {
					for (const key of SYNTHETIC_KEYS) {
						const value = deps[key];
						if (typeof value !== "object" || value === null) continue;
						before.set(key, Object.getOwnPropertyDescriptors(value));
						const nested = nestedObjectOf(value);
						if (nested !== undefined) {
							nestedBefore.set(key, Object.getOwnPropertyDescriptors(nested));
						}
						const targets: [string, object][] = [[key, value]];
						if (nested !== undefined) targets.push([`${key} (nested)`, nested]);
						for (const [label, target] of targets) {
							// Deleting a member an object does not hold succeeds even when
							// it is frozen: the writes on a member need one to aim at.
							const [member] = Reflect.ownKeys(target);
							for (const [write, run] of Object.entries(WRITES)) {
								if (member === undefined && MEMBER_WRITES.has(write)) continue;
								try {
									run(target, member ?? "tampered");
									refused[`${label} ${write}`] = "allowed";
								} catch (err) {
									refused[`${label} ${write}`] = (err as Error).constructor.name;
								}
							}
						}
					}
					return {};
				},
			} as never,
		});
		const seen: Record<string, unknown> = {};
		const reader: Module = defineModule({
			name: "test:projection-reader",
			requires: [...SYNTHETIC_KEYS, "test.projectionMutator"] as never,
			provides: {
				"test.projectionReader": (deps: Record<string, unknown>) => {
					for (const key of SYNTHETIC_KEYS) seen[key] = deps[key];
					return {};
				},
			} as never,
		});

		// What pulls both providers into the composition.
		const user: Module = defineModule({
			name: "test:projection-user",
			requires: ["test.projectionReader"] as never,
			contributes: { grantMiddleware: [() => null] },
		});

		const handle = await createApp({
			modules: [mutator, reader, user],
			bootstrapComponents: bootstrap(),
		});
		try {
			expect(before.size).toBeGreaterThan(0);
			expect(Object.entries(refused).filter(([, outcome]) => outcome !== "TypeError")).toEqual([]);
			for (const [key, descriptors] of before) {
				const value = seen[key] as object;
				expect(value, key).toBe((handle.components as Record<string, unknown>)[key]);
				expect(changedMembers(value, descriptors), key).toEqual([]);
				expect(Object.hasOwn(value, "tampered"), key).toBe(false);
			}
			for (const [key, descriptors] of nestedBefore) {
				const nested = nestedObjectOf(seen[key] as object) as object;
				expect(changedMembers(nested, descriptors), key).toEqual([]);
			}
			// The projections still answer as they did.
			expect(handle.components.grantHandlerResolver?.get("absent")).toBeUndefined();
			expect(handle.components.tokenBindingSettings).toEqual({
				dispatchPolicy: "intent-explicit",
				bindConfidentialClientRefreshTokens: false,
			});
			expect(handle.components.outboundPolicy?.allowedHosts).toHaveLength(1);
		} finally {
			await handle.dispose();
		}
	});

	it("leaves the registrars working: a provider registers through each, dispose drains the cleanup and the probe is probed", async () => {
		const events: string[] = [];
		const frozenWhenUsed: boolean[] = [];
		const registrarUser: Module = defineModule({
			name: "test:registrar-user",
			requires: ["lifecycleRegistrar", "readinessRegistrar"] as never,
			provides: {
				"test.registrarUser": (deps: Record<string, unknown>) => {
					const lifecycle = deps.lifecycleRegistrar as {
						register(cleanup: () => Promise<void>): void;
					};
					const readiness = deps.readinessRegistrar as {
						register(probe: { name: string; check(): Promise<unknown> }): void;
					};
					frozenWhenUsed.push(Object.isFrozen(lifecycle), Object.isFrozen(readiness));
					lifecycle.register(async () => {
						events.push("cleaned up");
					});
					readiness.register({
						name: "test-store",
						check: async () => {
							events.push("probed");
							return "ok";
						},
					});
					return {};
				},
			} as never,
			lifecycle: { "test.registrarUser": { eager: true } } as never,
		});

		const handle = await createApp({ modules: [registrarUser], bootstrapComponents: bootstrap() });
		let disposed = false;
		try {
			expect(frozenWhenUsed).toEqual([true, true]);
			expect(handle.readinessProbes.map((probe) => probe.name)).toEqual(["test-store"]);
			const report = await runReadinessProbes(handle.readinessProbes, { timeoutMs: 1_000 });
			expect(report.ready).toBe(true);
			expect(events).toEqual(["probed"]);
			await handle.dispose();
			disposed = true;
			expect(events).toEqual(["probed", "cleaned up"]);
		} finally {
			if (!disposed) await handle.dispose();
		}
	});

	it("refuses a write through the components a running app exposes", async () => {
		const handle = await createApp({ modules: [], bootstrapComponents: bootstrap() });
		try {
			const resolver = handle.components.mfaFactorResolver as unknown as Record<string, unknown>;
			const original = resolver.get;
			expect(() => {
				resolver.get = () => undefined;
			}).toThrow(TypeError);
			expect(resolver.get).toBe(original);
		} finally {
			await handle.dispose();
		}
	});

	it("freezes a projection stage 4 injects when stage 3 was given no contribution kinds", async () => {
		const bootstrapComponents = bootstrap();
		const validated = validateManifests({ modules: [], bootstrapComponents });
		const plan = planBoot(validated, bootstrapComponents, undefined);
		const material = await materializeComponents(plan, bootstrapComponents, undefined);
		const kinds = mergeWithBuiltins(undefined);
		await applyContributions(material, kinds);
		const components = material.components as Readonly<Record<string, unknown>>;
		expect(Object.hasOwn(components, "grantHandlerResolver")).toBe(true);
		expect(unfrozenPath(components.grantHandlerResolver)).toBeUndefined();
	});
});

describe("freezeSyntheticSlots", () => {
	it("freezes a synthetic slot's plain objects and arrays all the way down", () => {
		const settings = { nested: { list: [{ leaf: 1 }] } };
		freezeSyntheticSlots({ federationSettings: settings });
		expect(unfrozenPath(settings)).toBeUndefined();
	});

	it("leaves a value under any other key as its provider made it", () => {
		const provided = { nested: { leaf: 1 } };
		freezeSyntheticSlots({ "test.projectionReader": provided });
		expect(Object.isFrozen(provided)).toBe(false);
		expect(Object.isFrozen(provided.nested)).toBe(false);
	});

	it("does not reach into an object that is not plain data", () => {
		const inner = { leaf: 1 };
		const map = new Map([["k", inner]]);
		const settings = { map };
		freezeSyntheticSlots({ federationSettings: settings });
		expect(Object.isFrozen(settings)).toBe(true);
		expect(Object.isFrozen(map)).toBe(false);
		expect(Object.isFrozen(inner)).toBe(false);
	});

	it("does not read an accessor to freeze what it answers", () => {
		let reads = 0;
		const view = {
			get size() {
				reads++;
				return 0;
			},
		};
		freezeSyntheticSlots({ federationProviders: view });
		expect(Object.isFrozen(view)).toBe(true);
		expect(reads).toBe(0);
	});
});
