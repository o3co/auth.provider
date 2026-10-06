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
 * A module's own configuration section, delivered by boot: the
 * manifest's `section.schema` parses the value at `section.at` (the module's
 * name when unset) out of the configuration boot already has, and every
 * factory of the module — `provides`, name-keyed and list-shaped
 * `contributes`, `overrides` — receives the parsed value as `deps.section`.
 * A value the schema refuses refuses boot, naming the path the operator
 * wrote. A module that declares no section is booted exactly as before.
 */

import { describe, expect, it } from "vitest";
import { z } from "zod";
import { defineModule } from "../../modules/manifest/index.mjs";
import { makeValidCoreConfig } from "../../testing/fixtures/valid-config.mjs";
import { createTestMfaFactor } from "../../testing/mfaFactor.mjs";
import { createApp } from "../create-app.mjs";
import type { BootstrapMap } from "../types.mjs";
import { BootError } from "../types.mjs";

declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly sectionFixtureSlot: number;
	}
}

/** Coerces, so a delivered `3` proves the section was parsed, not handed over raw. */
const RetrySection = z.object({
	retries: z.coerce.number().int().positive(),
	label: z.string().optional(),
});

const bootWith = (extra: Record<string, unknown>): BootstrapMap =>
	({
		config: { ...makeValidCoreConfig(), ...extra } as never,
		pathResolver: (s: string) => s,
	}) satisfies Record<string, unknown> as BootstrapMap;

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

describe("a module's section — delivered as deps.section", () => {
	it("every factory of the module receives its section, parsed by its schema", async () => {
		const seen: Record<string, unknown> = {};
		// A module the sectioned one overrides, so the override position runs
		// too. Its factor is switched on: a switched-off one is no override target.
		const base = defineModule({
			name: "section-base",
			contributes: {
				mfaFactors: { "fixture-factor": () => createTestMfaFactor({ kind: "fixture-factor" }) },
			},
		});
		const sectioned = defineModule({
			name: "fixture-section",
			section: { schema: RetrySection },
			provides: {
				sectionFixtureSlot: (deps) => {
					seen.provides = deps.section;
					return deps.section.retries;
				},
			},
			lifecycle: { sectionFixtureSlot: { eager: true } },
			contributes: {
				grantMiddleware: [
					(deps) => {
						seen.listShaped = deps.section;
						return null;
					},
				],
				mfaFactors: {
					"fixture-own-factor": (deps) => {
						seen.nameKeyed = deps.section;
						return null;
					},
				},
			},
			overrides: {
				mfaFactors: {
					"fixture-factor": (deps) => {
						seen.overrides = deps.section;
						return null;
					},
				},
			},
		});

		const handle = await createApp({
			modules: [base, sectioned],
			bootstrapComponents: bootWith({ "fixture-section": { retries: "3" } }),
		});

		const parsed = { retries: 3 };
		expect(seen).toEqual({
			provides: parsed,
			listShaped: parsed,
			nameKeyed: parsed,
			overrides: parsed,
		});
		expect(handle.components.sectionFixtureSlot).toBe(3);
		await handle.dispose();
	});

	it("reads the section at `at` when the manifest names a transitional path", async () => {
		let seen: unknown;
		const sectioned = defineModule({
			name: "fixture-section",
			section: { schema: RetrySection, at: "legacy.fixture" },
			contributes: {
				grantMiddleware: [
					(deps) => {
						seen = deps.section;
						return null;
					},
				],
			},
		});

		const handle = await createApp({
			modules: [sectioned],
			bootstrapComponents: bootWith({
				legacy: { fixture: { retries: "5", label: "old home" } },
				// The module's name is not where this section is read from.
				"fixture-section": { retries: "not read" },
			}),
		});

		expect(seen).toEqual({ retries: 5, label: "old home" });
		await handle.dispose();
	});

	it("writes the parsed section back into the config slot, at its path", async () => {
		let config: unknown;
		let section: unknown;
		const sectioned = defineModule({
			name: "fixture-section",
			requires: ["config"],
			section: { schema: RetrySection },
			contributes: {
				grantMiddleware: [
					(deps) => {
						config = deps.config;
						section = deps.section;
						return null;
					},
				],
			},
		});

		const handle = await createApp({
			modules: [sectioned],
			bootstrapComponents: bootWith({ "fixture-section": { retries: "3" } }),
		});

		expect(section).toEqual({ retries: 3 });
		expect((config as Record<string, unknown>)["fixture-section"]).toEqual({ retries: 3 });
		await handle.dispose();
	});

	it("declares reference without acting on it: nothing is read", async () => {
		let seen: unknown;
		const sectioned = defineModule({
			name: "fixture-section",
			section: {
				schema: RetrySection,
				reference: new URL("file:///nonexistent/config/reference.conf"),
			},
			contributes: {
				grantMiddleware: [
					(deps) => {
						seen = deps.section;
						return null;
					},
				],
			},
		});

		const handle = await createApp({
			modules: [sectioned],
			bootstrapComponents: bootWith({
				"fixture-section": { retries: "2" },
			}),
		});

		expect(seen).toEqual({ retries: 2 });
		await handle.dispose();
	});
});

describe("a module's section — a value its schema refuses refuses boot", () => {
	it("names the operator's path, and no factory runs", async () => {
		let ran = false;
		const sectioned = defineModule({
			name: "fixture-section",
			section: { schema: RetrySection },
			contributes: {
				grantMiddleware: [
					() => {
						ran = true;
						return null;
					},
				],
			},
		});

		const err = await refusal(
			createApp({
				modules: [sectioned],
				bootstrapComponents: bootWith({ "fixture-section": { retries: "many" } }),
			}),
		);

		expect(err.reason).toBe("config-validation-failed");
		expect(err.stage).toBe("validateManifests");
		expect(err.message).toContain("fixture-section.retries");
		expect(err.details).toMatchObject({
			reason: "config-validation-failed",
			issues: [expect.objectContaining({ path: ["fixture-section", "retries"] })],
			modules: [{ module: "fixture-section", schemaPath: "fixture-section" }],
		});
		expect(ran).toBe(false);
	});

	it("names the transitional path when the section is read at `at`", async () => {
		const sectioned = defineModule({
			name: "fixture-section",
			section: { schema: RetrySection, at: "legacy.fixture" },
		});

		const err = await refusal(
			createApp({
				modules: [sectioned],
				bootstrapComponents: bootWith({ legacy: { fixture: { retries: -1 } } }),
			}),
		);

		expect(err.reason).toBe("config-validation-failed");
		expect(err.message).toContain("legacy.fixture.retries");
		expect(err.details).toMatchObject({
			issues: [expect.objectContaining({ path: ["legacy", "fixture", "retries"] })],
			modules: [{ module: "fixture-section", schemaPath: "legacy.fixture" }],
		});
	});

	it("refuses a missing section its schema requires, naming the section", async () => {
		const sectioned = defineModule({
			name: "fixture-section",
			section: { schema: RetrySection },
		});

		const err = await refusal(
			createApp({ modules: [sectioned], bootstrapComponents: bootWith({}) }),
		);

		expect(err.reason).toBe("config-validation-failed");
		expect(err.message).toContain("fixture-section");
		expect(err.details).toMatchObject({
			issues: [expect.objectContaining({ path: ["fixture-section"] })],
			modules: [{ module: "fixture-section", schemaPath: "fixture-section" }],
		});
	});

	it("reports every refused section at once, in module order", async () => {
		const first = defineModule({ name: "fixture-first", section: { schema: RetrySection } });
		const fine = defineModule({ name: "fixture-fine", section: { schema: RetrySection } });
		const second = defineModule({ name: "fixture-second", section: { schema: RetrySection } });

		const err = await refusal(
			createApp({
				modules: [first, fine, second],
				bootstrapComponents: bootWith({
					"fixture-first": { retries: 0 },
					"fixture-fine": { retries: 1 },
					"fixture-second": { retries: "x" },
				}),
			}),
		);

		expect(err.message).toContain("fixture-first.retries");
		expect(err.message).toContain("fixture-second.retries");
		expect(err.details).toMatchObject({
			issues: [
				expect.objectContaining({ path: ["fixture-first", "retries"] }),
				expect.objectContaining({ path: ["fixture-second", "retries"] }),
			],
			modules: [
				{ module: "fixture-first", schemaPath: "fixture-first" },
				{ module: "fixture-second", schemaPath: "fixture-second" },
			],
		});
	});
});

describe("a module without a section", () => {
	it("boots with deps that carry no section key", async () => {
		let keys: readonly string[] | undefined;
		const plain = defineModule({
			name: "fixture-plain",
			requires: ["config"],
			contributes: {
				grantMiddleware: [
					(deps) => {
						keys = Object.keys(deps);
						return null;
					},
				],
			},
		});

		const handle = await createApp({
			modules: [plain],
			// A value at the module's name is not a section it declared: nothing parses it.
			bootstrapComponents: bootWith({ "fixture-plain": { retries: "not a number" } }),
		});

		expect(keys).toEqual(["config"]);
		await handle.dispose();
	});
});

describe("a module's section — read from the parsed configuration", () => {
	it("sees what core's schema made of the path: coerced, with the keys core does not declare kept", async () => {
		// The choice pinned: the section is read out of the composed parse's
		// output — core's schema laid over what was written. Under a
		// parent core's schema declares, a value core coerces arrives coerced —
		// so a section read raw would refuse `maxLength: "128"` — and a key
		// core does not declare is still there.
		let seen: unknown;
		const sectioned = defineModule({
			name: "fixture-section",
			section: {
				schema: z.object({ maxLength: z.number(), extra: z.string().optional() }),
				at: "oauth.nonce",
			},
			contributes: {
				grantMiddleware: [
					(deps) => {
						seen = deps.section;
						return null;
					},
				],
			},
		});

		const handle = await createApp({
			modules: [sectioned],
			bootstrapComponents: bootWith({
				oauth: { ...makeValidCoreConfig().oauth, nonce: { maxLength: "128", extra: "kept" } },
			}),
		});

		expect(seen).toEqual({ maxLength: 128, extra: "kept" });
		await handle.dispose();
	});

	it("reads own keys only: a path segment an object inherits is absent", async () => {
		let seen: unknown = "unset";
		const sectioned = defineModule({
			name: "fixture-section",
			section: { schema: z.unknown(), at: "constructor" },
			contributes: {
				grantMiddleware: [
					(deps) => {
						seen = deps.section;
						return null;
					},
				],
			},
		});

		const handle = await createApp({ modules: [sectioned], bootstrapComponents: bootWith({}) });

		expect(seen).toBeUndefined();
		await handle.dispose();
	});

	it("reads a module's name as one key, never split on its dots", async () => {
		let seen: unknown;
		const sectioned = defineModule({
			name: "fixture.section",
			section: { schema: RetrySection },
			contributes: {
				grantMiddleware: [
					(deps) => {
						seen = deps.section;
						return null;
					},
				],
			},
		});

		const handle = await createApp({
			modules: [sectioned],
			bootstrapComponents: bootWith({
				"fixture.section": { retries: 1 },
				fixture: { section: { retries: 2 } },
			}),
		});

		expect(seen).toEqual({ retries: 1 });
		await handle.dispose();
	});

	it("hands an absent section a schema accepts as `undefined`, under a `section` key that is there", async () => {
		let deps: Record<string, unknown> | undefined;
		const sectioned = defineModule({
			name: "fixture-section",
			section: { schema: RetrySection.optional() },
			contributes: {
				grantMiddleware: [
					(given) => {
						deps = given as Record<string, unknown>;
						return null;
					},
				],
			},
		});

		const handle = await createApp({ modules: [sectioned], bootstrapComponents: bootWith({}) });

		expect(deps !== undefined && "section" in deps).toBe(true);
		expect(deps?.section).toBeUndefined();
		await handle.dispose();
	});
});

describe("a module's section — one frozen object", () => {
	it("hands every factory the same deeply frozen section, apart from the config slot", async () => {
		const seen: unknown[] = [];
		let config: Record<string, unknown> | undefined;
		const sectioned = defineModule({
			name: "fixture-section",
			requires: ["config"],
			section: {
				schema: z.object({
					nested: z.object({ list: z.array(z.number()) }),
					free: z.unknown(),
				}),
			},
			provides: {
				sectionFixtureSlot: (deps) => {
					seen.push(deps.section);
					return 1;
				},
			},
			lifecycle: { sectionFixtureSlot: { eager: true } },
			contributes: {
				grantMiddleware: [
					(deps) => {
						seen.push(deps.section);
						config = deps.config as unknown as Record<string, unknown>;
						return null;
					},
				],
			},
		});

		const handle = await createApp({
			modules: [sectioned],
			bootstrapComponents: bootWith({
				"fixture-section": { nested: { list: [1, 2] }, free: { deep: { value: 1 } } },
			}),
		});

		const [first, second] = seen as [
			{ nested: { list: number[] }; free: { deep: { value: number } } },
			unknown,
		];
		expect(second).toBe(first);
		expect(Object.isFrozen(first)).toBe(true);
		expect(Object.isFrozen(first.nested)).toBe(true);
		expect(Object.isFrozen(first.nested.list)).toBe(true);
		expect(Object.isFrozen(first.free)).toBe(true);
		expect(Object.isFrozen(first.free.deep)).toBe(true);
		// A subtree the schema passed through is a copy: the config slot's own is
		// not the section's, and is frozen by boot's freeze of the slot.
		expect(config).toBeDefined();
		const raw = (config?.["fixture-section"] as { free: { deep: object } } | undefined)?.free;
		expect(raw).toBeDefined();
		if (raw === undefined) return;
		expect(raw).not.toBe(first.free);
		expect(Object.isFrozen(raw.deep)).toBe(true);
		await handle.dispose();
	});

	it("hands over a value that is not plain data as the schema made it", async () => {
		let seen: { url: URL; key: Buffer } | undefined;
		const sectioned = defineModule({
			name: "fixture-section",
			section: {
				schema: z.object({
					url: z.string().transform((value) => new URL(value)),
					key: z.string().transform((value) => Buffer.from(value, "utf8")),
				}),
			},
			contributes: {
				grantMiddleware: [
					(deps) => {
						seen = deps.section;
						return null;
					},
				],
			},
		});

		const handle = await createApp({
			modules: [sectioned],
			bootstrapComponents: bootWith({
				"fixture-section": { url: "https://idp.example/a", key: "k" },
			}),
		});

		expect(seen?.url).toBeInstanceOf(URL);
		expect(seen?.url.href).toBe("https://idp.example/a");
		expect(Buffer.isBuffer(seen?.key)).toBe(true);
		expect(seen?.key.toString("utf8")).toBe("k");
		await handle.dispose();
	});
});

describe("a module's section — refused, more", () => {
	it("names every refused key of one section", async () => {
		const sectioned = defineModule({
			name: "fixture-section",
			section: { schema: RetrySection },
		});

		const err = await refusal(
			createApp({
				modules: [sectioned],
				bootstrapComponents: bootWith({ "fixture-section": { retries: 0, label: 7 } }),
			}),
		);

		expect(err.message).toContain("fixture-section.retries");
		expect(err.message).toContain("fixture-section.label");
		expect(err.details).toMatchObject({
			issues: [
				expect.objectContaining({ path: ["fixture-section", "retries"] }),
				expect.objectContaining({ path: ["fixture-section", "label"] }),
			],
			modules: [{ module: "fixture-section", schemaPath: "fixture-section" }],
		});
	});

	it("is refused before the post-config rows run", async () => {
		// Under "multi" the replica-safety row would refuse this module; the
		// section's refusal comes first.
		const sectioned = defineModule({
			name: "fixture-section",
			section: { schema: RetrySection },
			replicaSafety: { unsafe: true, reason: "state forks per replica" },
		});

		const err = await refusal(
			createApp({
				modules: [sectioned],
				bootstrapComponents: bootWith({
					core: { deployment: { mode: "multi" } },
					"fixture-section": { retries: "x" },
				}),
			}),
		);

		expect(err.reason).toBe("config-validation-failed");
	});

	it("is parsed for every installed module, one whose provider is overridden included", async () => {
		const sectioned = defineModule({
			name: "fixture-section",
			section: { schema: RetrySection },
			provides: { sectionFixtureSlot: () => 1 },
		});

		const err = await refusal(
			createApp({
				modules: [sectioned],
				bootstrapComponents: bootWith({ "fixture-section": { retries: "x" } }),
				overrideComponents: { sectionFixtureSlot: 2 },
			}),
		);

		expect(err.reason).toBe("config-validation-failed");
		expect(err.message).toContain("fixture-section.retries");
	});

	it.each([
		["an async refinement", RetrySection.refine(async () => true)],
		[
			"a transform that throws",
			RetrySection.transform(() => {
				throw new Error("transform failed");
			}),
		],
	])(
		"a schema that cannot answer synchronously — %s — is refused naming the section",
		async (_label, schema) => {
			const sectioned = defineModule({ name: "fixture-section", section: { schema } });

			const err = await refusal(
				createApp({
					modules: [sectioned],
					bootstrapComponents: bootWith({ "fixture-section": { retries: 1 } }),
				}),
			);

			expect(err.reason).toBe("config-validation-failed");
			expect(err.stage).toBe("validateManifests");
			expect(err.message).toContain("fixture-section: ");
			expect(err.details).toMatchObject({
				issues: [expect.objectContaining({ code: "custom", path: ["fixture-section"] })],
				modules: [{ module: "fixture-section", schemaPath: "fixture-section" }],
			});
		},
	);
});

describe("a module's section — manifest refusals", () => {
	it.each(["", "a..b", ".a", "a."])("refuses `at: %j`, a path with an empty key", async (at) => {
		const sectioned = defineModule({
			name: "fixture-section",
			section: { schema: RetrySection, at },
		});

		const err = await refusal(
			createApp({ modules: [sectioned], bootstrapComponents: bootWith({}) }),
		);

		expect(err.reason).toBe("module-section-path-invalid");
		expect(err.stage).toBe("validateManifests");
		expect(err.details).toEqual({
			reason: "module-section-path-invalid",
			module: "fixture-section",
			at,
		});
	});

	it.each<[string, unknown]>([
		["a bigint", 1n],
		[
			"a cyclic object",
			(() => {
				const cyclic: Record<string, unknown> = {};
				cyclic.self = cyclic;
				return cyclic;
			})(),
		],
		["a number", 7],
	])(
		"refuses `at` that is not a string — %s — naming its type, the value kept in details",
		async (_label, at) => {
			const sectioned = defineModule({
				name: "fixture-section",
				section: { schema: RetrySection, at: at as never },
			});

			const err = await refusal(
				createApp({ modules: [sectioned], bootstrapComponents: bootWith({}) }),
			);

			expect(err.reason).toBe("module-section-path-invalid");
			expect(err.message).toContain(`a ${typeof at}`);
			expect(err.details).toEqual({
				reason: "module-section-path-invalid",
				module: "fixture-section",
				at,
			});
			expect((err.details as { at: unknown }).at).toBe(at);
		},
	);

	const noop = { grantMiddleware: [() => null] };

	it.each([
		["requires", { requires: ["section"] as never }, "module-requires"],
		["optionally reads", { optional: ["section"] as never }, "module-optional"],
	])(
		"refuses a sectioned module that %s a component named `section`: its deps would carry both under one key",
		async (_label, reads, source) => {
			const sectioned = defineModule({
				name: "fixture-section",
				section: { schema: RetrySection },
				contributes: noop,
				...reads,
			});
			const slot = defineModule({ name: "fixture-slot", provides: { section: () => 1 } as never });

			const err = await refusal(
				createApp({
					modules: [slot, sectioned],
					bootstrapComponents: bootWith({ "fixture-section": { retries: 1 } }),
				}),
			);

			expect(err.reason).toBe("reserved-component-key");
			expect(err.stage).toBe("validateManifests");
			expect(err.details).toEqual({
				reason: "reserved-component-key",
				componentKey: "section",
				source,
				module: "fixture-section",
			});
		},
	);

	it("boots a component named `section` that no sectioned module reads — provided, required, bootstrapped and overridden", async () => {
		let read: unknown;
		const provider = defineModule({
			name: "fixture-slot",
			provides: { section: () => "provided" } as never,
		});
		const reader = defineModule({
			name: "fixture-reader",
			requires: ["section"] as never,
			contributes: {
				grantMiddleware: [
					(deps: Record<string, unknown>) => {
						read = deps.section;
						return null;
					},
				],
			} as never,
		});
		const sectioned = defineModule({
			name: "fixture-section",
			section: { schema: RetrySection },
			contributes: noop,
		});

		const handle = await createApp({
			modules: [provider, reader, sectioned],
			bootstrapComponents: bootWith({ "fixture-section": { retries: 1 } }),
			overrideComponents: { section: "overridden" } as never,
		});

		// The reader declares no section, so its `section` is the slot's value.
		expect(read).toBe("overridden");
		await handle.dispose();

		const bootstrapped = await createApp({
			modules: [reader],
			bootstrapComponents: { ...bootWith({}), section: "bootstrapped" } as BootstrapMap,
		});
		expect(read).toBe("bootstrapped");
		await bootstrapped.dispose();
	});
});
