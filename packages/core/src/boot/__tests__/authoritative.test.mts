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
 * `ModuleSpec.authoritative` (#728): the keys a module provides that no
 * composition may substitute while the module is loaded, because other
 * modules read them as that module's own settings, derived from its section.
 * An override is a second source for them by construction, and the module's
 * own code would go on reading the section while every other reader followed
 * the override.
 *
 * - A key a module names authoritative and does not provide refuses boot
 *   (`authoritative-without-provides`), as a lifecycle for an unprovided key
 *   does.
 * - An `overrideComponents` entry for an authoritative key of a loaded module
 *   refuses boot (`authoritative-component-overridden`), naming the module
 *   and the key.
 * - A `bootstrapComponents` entry for it is refused as for any provided key
 *   (`bootstrap-component-collision`).
 * - With the module not loaded, an override of the key is allowed: a
 *   composition without the owner fills the slot itself. And a key the module
 *   provides without naming it authoritative may be overridden, as before.
 */

import { describe, expect, expectTypeOf, it } from "vitest";
import type {
	AuthoritativeComponentOverriddenDetails,
	AuthoritativeWithoutProvidesDetails,
	BootErrorDetails,
} from "../../index.mjs";
import { createApp } from "../../index.mjs";
import { defineModule, type Module } from "../../modules/manifest/index.mjs";
import { makeValidCoreConfig } from "../../testing/fixtures/valid-config.mjs";
import { createTestHttpSettings } from "../../testing/slots/httpSettings.mjs";
import { createTestOAuthTokenSettings } from "../../testing/slots/oauthTokenSettings.mjs";
import type { OAuthTokenSettings } from "../../token-settings/types.mjs";
import { BootError } from "../types.mjs";

const OWNED = createTestOAuthTokenSettings({ issuer: "https://owner.test" });
const SECOND = createTestOAuthTokenSettings({ issuer: "https://second.test" });

/** A module that provides the settings and names them authoritative. */
const owner = defineModule({
	name: "test:owner",
	provides: { oauthTokenSettings: () => OWNED },
	authoritative: ["oauthTokenSettings"],
});

/** The same, without naming them authoritative. */
const plainOwner = defineModule({
	name: "test:plain-owner",
	provides: { oauthTokenSettings: () => OWNED },
});

/** A module that requires the settings, and keeps what it was handed. */
const reader = (seen: { settings?: OAuthTokenSettings }) =>
	defineModule({
		name: "test:reader",
		requires: ["oauthTokenSettings"],
		contributes: {
			routes: [
				(deps) => {
					seen.settings = deps.oauthTokenSettings;
					return {
						id: "test-reader",
						mountPath: "/__test_reader__",
						handler: ((_req: unknown, _res: unknown, next: () => void) => next()) as never,
					};
				},
			],
		},
	});

const bootstrap = () =>
	({ config: makeValidCoreConfig(), pathResolver: (p: string) => p }) as never;

const refusal = async (booting: Promise<unknown>): Promise<BootError> => {
	const caught = await booting.then(
		() => undefined,
		(err: unknown) => err,
	);
	expect(caught).toBeInstanceOf(BootError);
	return caught as BootError;
};

describe("ModuleSpec.authoritative (#728)", () => {
	it("publishes both reasons' details on the package's root, as members of BootErrorDetails", () => {
		expectTypeOf<AuthoritativeWithoutProvidesDetails>().toExtend<BootErrorDetails>();
		expectTypeOf<AuthoritativeComponentOverriddenDetails>().toExtend<BootErrorDetails>();
		expectTypeOf<AuthoritativeComponentOverriddenDetails>().toEqualTypeOf<
			Extract<BootErrorDetails, { reason: "authoritative-component-overridden" }>
		>();
	});

	it("refuses a key the module names authoritative and does not provide", async () => {
		const err = await refusal(
			createApp({
				modules: [
					defineModule({
						name: "test:unprovided",
						provides: {},
						authoritative: ["oauthTokenSettings"] as never,
					}),
				],
				bootstrapComponents: bootstrap(),
			}),
		);
		expect(err.reason).toBe("authoritative-without-provides");
		expect(err.stage).toBe("validateManifests");
		expect(err.details).toEqual({
			reason: "authoritative-without-provides",
			module: "test:unprovided",
			componentKey: "oauthTokenSettings",
		});
	});

	it.each<[string, unknown, string]>([
		["a string", "oauthTokenSettings", 'the string "oauthTokenSettings"'],
		["null", null, "null"],
		["a number", 5, "the number 5"],
		["a Set", new Set(["oauthTokenSettings"]), "a Set"],
		["a plain object", { oauthTokenSettings: true }, "an Object"],
	])(
		"refuses an authoritative that is %s, not a list of keys, saying what it is",
		async (_label, declared, described) => {
			const err = await refusal(
				createApp({
					modules: [
						defineModule({
							name: "test:not-a-list",
							provides: { oauthTokenSettings: () => OWNED },
							authoritative: declared as never,
						}),
					],
					bootstrapComponents: bootstrap(),
				}),
			);
			expect(err.reason).toBe("authoritative-without-provides");
			// Refused as a value, not read character by character as a list of
			// keys; no key is named, since none was.
			expect(err.details).toEqual({
				reason: "authoritative-without-provides",
				module: "test:not-a-list",
				declared: described,
			});
			expect(err.message).toContain(`declares authoritative as ${described}, not a list`);
		},
	);

	it("names a key that is not a string without rendering it: a null-prototype object is described, not thrown on", async () => {
		const err = await refusal(
			createApp({
				modules: [
					defineModule({
						name: "test:odd-key",
						provides: { oauthTokenSettings: () => OWNED },
						authoritative: [Object.create(null)] as never,
					}),
				],
				bootstrapComponents: bootstrap(),
			}),
		);
		expect(err.reason).toBe("authoritative-without-provides");
		expect(err.details).toEqual({
			reason: "authoritative-without-provides",
			module: "test:odd-key",
			componentKey: "an object",
		});
	});

	it("reads a manifest's authoritative once", async () => {
		let reads = 0;
		const counted = {
			name: "test:counted",
			provides: { oauthTokenSettings: () => OWNED },
			get authoritative() {
				reads += 1;
				return ["oauthTokenSettings"];
			},
		} as unknown as Module;
		const handle = await createApp({ modules: [counted], bootstrapComponents: bootstrap() });
		await handle.dispose();
		expect(reads).toBe(1);
	});

	it("refuses an override of an authoritative key of a loaded module, naming the module and the key", async () => {
		const err = await refusal(
			createApp({
				modules: [owner, reader({})],
				bootstrapComponents: bootstrap(),
				overrideComponents: { oauthTokenSettings: SECOND },
			}),
		);
		expect(err.reason).toBe("authoritative-component-overridden");
		expect(err.stage).toBe("validateManifests");
		expect(err.details).toEqual({
			reason: "authoritative-component-overridden",
			module: "test:owner",
			componentKey: "oauthTokenSettings",
		});
		expect(err.message).toMatch(/test:owner/);
		expect(err.message).toMatch(/oauthTokenSettings/);
		expect(err.message).toMatch(/its own section/);
		expect(err.message).toMatch(/split/);
	});

	it("refuses a bootstrap component for an authoritative key of a loaded module, as for any provided key", async () => {
		const err = await refusal(
			createApp({
				modules: [owner, reader({})],
				bootstrapComponents: {
					config: makeValidCoreConfig(),
					pathResolver: (p: string) => p,
					oauthTokenSettings: SECOND,
				} as never,
			}),
		);
		expect(err.reason).toBe("bootstrap-component-collision");
		expect(err.details).toMatchObject({
			componentKey: "oauthTokenSettings",
			source: "module-provides",
			module: "test:owner",
		});
	});

	it("allows an override of the key when the providing module is not loaded: the composition fills the slot itself", async () => {
		const seen: { settings?: OAuthTokenSettings } = {};
		const handle = await createApp({
			modules: [reader(seen)],
			bootstrapComponents: bootstrap(),
			overrideComponents: { oauthTokenSettings: SECOND },
		});
		try {
			expect(seen.settings).toBe(SECOND);
		} finally {
			await handle.dispose();
		}
	});

	it("allows an override of a key the loaded module provides without naming it authoritative, as before", async () => {
		const seen: { settings?: OAuthTokenSettings } = {};
		const handle = await createApp({
			modules: [plainOwner, reader(seen)],
			bootstrapComponents: bootstrap(),
			overrideComponents: { oauthTokenSettings: SECOND },
		});
		try {
			expect(seen.settings).toBe(SECOND);
		} finally {
			await handle.dispose();
		}
	});

	it("hands the owner's value to its readers when nothing substitutes it", async () => {
		const seen: { settings?: OAuthTokenSettings } = {};
		const handle = await createApp({
			modules: [owner, reader(seen)],
			bootstrapComponents: bootstrap(),
		});
		try {
			expect(seen.settings).toBe(OWNED);
		} finally {
			await handle.dispose();
		}
	});
});

describe("ModuleSpec.authoritative — every module, every key, the keys materialize reads", () => {
	const HTTP = createTestHttpSettings();

	it("refuses the override when the owner is listed after its reader", async () => {
		const err = await refusal(
			createApp({
				modules: [reader({}), owner],
				bootstrapComponents: bootstrap(),
				overrideComponents: { oauthTokenSettings: SECOND },
			}),
		);
		expect(err.details).toEqual({
			reason: "authoritative-component-overridden",
			module: "test:owner",
			componentKey: "oauthTokenSettings",
		});
	});

	it("refuses an override of the second of two authoritative keys when the first is not overridden", async () => {
		const both = defineModule({
			name: "test:both",
			provides: { oauthTokenSettings: () => OWNED, httpSettings: () => HTTP },
			authoritative: ["oauthTokenSettings", "httpSettings"],
		});
		const err = await refusal(
			createApp({
				modules: [both],
				bootstrapComponents: bootstrap(),
				overrideComponents: { httpSettings: createTestHttpSettings({ trustProxy: true }) },
			}),
		);
		expect(err.details).toEqual({
			reason: "authoritative-component-overridden",
			module: "test:both",
			componentKey: "httpSettings",
		});
	});

	it("reads every authoritative key: the second, unprovided, is refused though the first is provided", async () => {
		const err = await refusal(
			createApp({
				modules: [
					defineModule({
						name: "test:second-unprovided",
						provides: { oauthTokenSettings: () => OWNED },
						authoritative: ["oauthTokenSettings", "httpSettings"] as never,
					}),
				],
				bootstrapComponents: bootstrap(),
			}),
		);
		expect(err.details).toEqual({
			reason: "authoritative-without-provides",
			module: "test:second-unprovided",
			componentKey: "httpSettings",
		});
	});

	it.each<[string, () => Partial<Record<string, unknown>>]>([
		["inherited", () => Object.create({ oauthTokenSettings: SECOND })],
		[
			"not enumerable",
			() => Object.defineProperty({}, "oauthTokenSettings", { value: SECOND, enumerable: false }),
		],
	])(
		"does not refuse an override key that is %s: materialize reads own enumerable keys alone, and the owner's value stands",
		async (_label, make) => {
			const seen: { settings?: OAuthTokenSettings } = {};
			const handle = await createApp({
				modules: [owner, reader(seen)],
				bootstrapComponents: bootstrap(),
				overrideComponents: make() as never,
			});
			try {
				expect(seen.settings).toBe(OWNED);
			} finally {
				await handle.dispose();
			}
		},
	);
});

describe("a __proto__ key in a host map", () => {
	// `components["__proto__"] = value` in materialize would replace the
	// working map's prototype: every key of the value would read as a
	// component, the owner's factory would be skipped, and its readers would
	// be handed the value — past the authoritative and collision checks, which
	// read the map's own keys.

	/** A map carrying `__proto__` as its own key, as a computed key or JSON.parse writes it. */
	const ways: readonly [string, () => Record<string, unknown>][] = [
		["written as a computed key", () => ({ ["__proto__"]: { oauthTokenSettings: SECOND } })],
		["parsed from JSON", () => JSON.parse('{"__proto__": {"oauthTokenSettings": {}}}')],
	];

	it.each(ways)(
		"refuses overrideComponents carrying __proto__ as its own key, %s",
		async (_label, make) => {
			const override = make();
			expect(Object.hasOwn(override, "__proto__")).toBe(true);
			const err = await refusal(
				createApp({
					modules: [owner, reader({})],
					bootstrapComponents: bootstrap(),
					overrideComponents: override as never,
				}),
			);
			expect(err.reason).toBe("reserved-component-key");
			expect(err.stage).toBe("validateManifests");
			expect(err.details).toEqual({
				reason: "reserved-component-key",
				componentKey: "__proto__",
				source: "overrideComponents",
			});
			expect(err.message).toContain("__proto__");
		},
	);

	it.each(ways)(
		"refuses bootstrapComponents carrying __proto__ as its own key, %s",
		async (_label, make) => {
			const host = make();
			host.config = makeValidCoreConfig();
			host.pathResolver = (p: string) => p;
			expect(Object.hasOwn(host, "__proto__")).toBe(true);
			const err = await refusal(
				createApp({ modules: [owner, reader({})], bootstrapComponents: host as never }),
			);
			expect(err.reason).toBe("reserved-component-key");
			expect(err.details).toEqual({
				reason: "reserved-component-key",
				componentKey: "__proto__",
				source: "bootstrapComponents",
			});
		},
	);
});

describe("the host maps are read once", () => {
	// Stage 1 checks a host map, and later stages read it again; a map that
	// answers differently on a later read — a Proxy, a getter — must not have
	// one answer checked and another used.
	it("does not substitute an authoritative key an override hides from its first read", async () => {
		let reads = 0;
		const hiding = new Proxy({ oauthTokenSettings: SECOND } as Record<string, unknown>, {
			ownKeys(target) {
				reads++;
				return reads === 1 ? [] : Reflect.ownKeys(target);
			},
		});
		const seen: { settings?: OAuthTokenSettings } = {};
		const handle = await createApp({
			modules: [owner, reader(seen)],
			bootstrapComponents: bootstrap(),
			overrideComponents: hiding as never,
		});
		try {
			expect(seen.settings).toBe(OWNED);
			expect(reads).toBe(1);
		} finally {
			await handle.dispose();
		}
	});

	it("reads an override's value once, however many stages use it", async () => {
		let reads = 0;
		const HTTP = createTestHttpSettings();
		const counting = {};
		Object.defineProperty(counting, "httpSettings", {
			enumerable: true,
			get() {
				reads++;
				return HTTP;
			},
		});
		const handle = await createApp({
			modules: [],
			bootstrapComponents: bootstrap(),
			overrideComponents: counting as never,
		});
		try {
			expect(reads).toBe(1);
		} finally {
			await handle.dispose();
		}
	});

	it("refuses an own __proto__ accessor without running it", async () => {
		let ran = 0;
		const host = {} as Record<string, unknown>;
		Object.defineProperty(host, "__proto__", {
			enumerable: true,
			get() {
				ran++;
				throw new Error("the accessor ran");
			},
		});
		const err = await refusal(
			createApp({
				modules: [owner, reader({})],
				bootstrapComponents: bootstrap(),
				overrideComponents: host as never,
			}),
		);
		expect(err.reason).toBe("reserved-component-key");
		expect(err.details).toEqual({
			reason: "reserved-component-key",
			componentKey: "__proto__",
			source: "overrideComponents",
		});
		expect(ran).toBe(0);
	});

	it("reads a bootstrap map's keys once", async () => {
		let reads = 0;
		const host = bootstrap() as Record<string, unknown>;
		const counted = new Proxy(host, {
			ownKeys(target) {
				reads++;
				return Reflect.ownKeys(target);
			},
		});
		const handle = await createApp({
			modules: [owner, reader({})],
			bootstrapComponents: counted as never,
		});
		try {
			expect(reads).toBe(1);
		} finally {
			await handle.dispose();
		}
	});
});
