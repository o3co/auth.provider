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
 * Boot's one composed parse (#728). A composition root hands `createApp` the
 * configuration it resolved — never parsed first — and boot parses it once:
 * with the transitional base (core's sections and every section core still
 * mirrors for a package, each optional), laid over what was written so
 * nothing is stripped; then with each module's `configSchema`, over the
 * base's output; then each module's section at its path, written back there.
 * A top-level section nobody owns is kept, and named once in the log.
 */

import { describe, expect, it, vi } from "vitest";
import { z } from "zod";
import type { AppConfig } from "../../config/application.schema.mjs";
import type { Logger } from "../../logging/Logger.mjs";
import { defineModule } from "../../modules/manifest/index.mjs";
import type { Module } from "../../modules/manifest/module-spec.mjs";
import { makeValidAppConfig, makeValidCoreConfig } from "../../testing/fixtures/valid-config.mjs";
import { createApp } from "../create-app.mjs";
import type { BootstrapMap } from "../types.mjs";
import { BootError } from "../types.mjs";

/** Coerces, so a `3` in the config slot proves the section was parsed and written back. */
const RetrySection = z.object({ retries: z.coerce.number().int().positive() });

/** A logger whose every method is a spy. */
function recordingLogger(): Logger & { readonly warn: ReturnType<typeof vi.fn> } {
	return {
		trace: vi.fn(),
		debug: vi.fn(),
		info: vi.fn(),
		warn: vi.fn(),
		error: vi.fn(),
		fatal: vi.fn(),
	} as unknown as Logger & { readonly warn: ReturnType<typeof vi.fn> };
}

/** A resolved configuration: core's sections, plus whatever `extra` adds at the top. */
const resolved = (extra: Record<string, unknown> = {}): Record<string, unknown> => ({
	...makeValidCoreConfig(),
	...extra,
});

/** Boots `modules` on `config`, as a composition root hands it over, and answers the parsed config slot. */
async function bootAndRead(
	modules: readonly Module[],
	config: Record<string, unknown>,
	logger: Logger = recordingLogger(),
): Promise<Record<string, unknown>> {
	const handle = await createApp({
		modules,
		bootstrapComponents: {
			config: config as unknown as AppConfig,
			pathResolver: (s: string) => s,
			logger,
		} satisfies Record<string, unknown> as BootstrapMap,
	});
	const parsed = handle.components.config as unknown as Record<string, unknown>;
	await handle.dispose();
	return parsed;
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

const bootRefused = (modules: readonly Module[], config: Record<string, unknown>) =>
	refusal(
		createApp({
			modules,
			bootstrapComponents: {
				config: config as unknown as AppConfig,
				pathResolver: (s: string) => s,
				logger: recordingLogger(),
			} satisfies Record<string, unknown> as BootstrapMap,
		}),
	);

/** A module whose section is `schema` at `at`, recording what its factory was handed. */
function sectioned(
	name: string,
	schema: z.ZodType,
	at: string | undefined,
	seen: Record<string, unknown> = {},
): Module {
	return defineModule({
		name,
		section: { schema, ...(at === undefined ? {} : { at }) },
		contributes: {
			grantMiddleware: [
				(deps) => {
					seen[name] = deps.section;
					return null;
				},
			],
		},
	});
}

describe("one composed parse over the transitional base", () => {
	it("coerces a section core mirrors that no loaded module owns, and keeps it", async () => {
		const config = await bootAndRead(
			[],
			resolved({ redisRateLimiter: { limits: { token: { limit: "120", windowSeconds: "60" } } } }),
		);
		expect(config.redisRateLimiter).toEqual({
			limits: { token: { limit: 120, windowSeconds: 60 } },
		});
	});

	it("refuses a value a mirrored section's schema refuses, naming the operator's path", async () => {
		const err = await bootRefused([], resolved({ deployment: { mode: "several" } }));
		expect(err.reason).toBe("config-validation-failed");
		expect(err.message).toMatch(/deployment\.mode: /);
	});

	it("names the configuration itself when it is not an object", async () => {
		const err = await bootRefused([], "http.port = 3000" as unknown as Record<string, unknown>);
		expect(err.reason).toBe("config-validation-failed");
		expect(err.message).toMatch(/: \(the configuration\): /);
	});

	it("names every refused path in the message", async () => {
		const err = await bootRefused(
			[],
			resolved({ http: { port: "not-a-port", trustProxy: false, readinessTimeoutMs: 0 } }),
		);
		expect(err.reason).toBe("config-validation-failed");
		expect(err.message).toMatch(/http\.port: /);
		expect(err.message).toMatch(/http\.readinessTimeoutMs: /);
	});

	it("keeps a key no schema declares under a section core declares", async () => {
		const config = await bootAndRead(
			[],
			resolved({ http: { ...makeValidCoreConfig().http, extra: "kept" } }),
		);
		expect((config.http as Record<string, unknown>).extra).toBe("kept");
	});

	it("hands a module's configSchema the base's output: an environment string arrives coerced", async () => {
		const strict = defineModule({
			name: "strict-reader",
			configSchema: z.object({ http: z.object({ port: z.number() }) }),
		});
		const config = await bootAndRead(
			[strict],
			resolved({ http: { port: "3000", trustProxy: false, readinessTimeoutMs: 1000 } }),
		);
		expect((config.http as Record<string, unknown>).port).toBe(3000);
	});

	it("reports only the base's refusals when the base refuses, not a module's schema reading what the base would have coerced", async () => {
		// Run over what was written, a module's schema would refuse the
		// environment string the base reads as a number: an error nobody made.
		const strict = defineModule({
			name: "strict-reader",
			configSchema: z.object({ http: z.object({ port: z.number() }) }),
		});
		const err = await bootRefused(
			[strict],
			resolved({
				http: { port: "3000", trustProxy: false, readinessTimeoutMs: 1000 },
				logging: { level: "loud" },
			}),
		);
		expect(err.reason).toBe("config-validation-failed");
		expect(err.message).toMatch(/logging\.level: /);
		expect(err.message).not.toMatch(/http\.port/);
		expect(
			(err.details as unknown as { issues: { path: PropertyKey[] }[] }).issues.map((issue) =>
				issue.path.join("."),
			),
		).toEqual(["logging.level"]);
	});

	describe("two modules' configSchemas that make different values of one key", () => {
		const coercing = defineModule({
			name: "coercing-reader",
			configSchema: z.object({ widget: z.object({ size: z.coerce.number() }) }),
		});
		const verbatim = defineModule({
			name: "verbatim-reader",
			configSchema: z.object({ widget: z.object({ size: z.string() }) }),
		});

		it.each([
			["coercing first", [coercing, verbatim]],
			["verbatim first", [verbatim, coercing]],
		])(
			"refuse boot, naming the key and both modules, whatever their order (%s)",
			async (_label, modules) => {
				const err = await bootRefused(modules, resolved({ widget: { size: "3" } }));
				expect(err.reason).toBe("config-validation-failed");
				expect(err.message).toMatch(/widget\.size: /);
				expect(err.message).toMatch(/"coercing-reader"/);
				expect(err.message).toMatch(/"verbatim-reader"/);
			},
		);

		const emptying = defineModule({
			name: "emptying-reader",
			configSchema: z.object({
				widget: z.object({ size: z.unknown().transform(() => ({})) }),
			}),
		});

		it.each([
			["the value first", [coercing, emptying]],
			["the empty object first", [emptying, coercing]],
		])(
			"refuse boot when one makes an empty object where another makes a value (%s)",
			async (_label, modules) => {
				// Laid over each other, the later one would win: an empty object
				// over the number, or the number over the empty object.
				const err = await bootRefused(modules, resolved({ widget: { size: "3" } }));
				expect(err.reason).toBe("config-validation-failed");
				expect(err.message).toMatch(/widget\.size: /);
				expect(err.message).toMatch(/"coercing-reader"/);
				expect(err.message).toMatch(/"emptying-reader"/);
			},
		);

		it("name each disagreeing key once, with the first two modules that disagree there", async () => {
			const alsoVerbatim = defineModule({
				name: "also-verbatim-reader",
				configSchema: z.object({
					widget: z.object({ size: z.string().transform((v) => `${v}!`) }),
				}),
			});
			const err = await bootRefused(
				[coercing, verbatim, alsoVerbatim],
				resolved({ widget: { size: "3" } }),
			);
			const issues = (
				err.details as unknown as { issues: { path: PropertyKey[]; message: string }[] }
			).issues;
			expect(issues.map((issue) => issue.path.join("."))).toEqual(["widget.size"]);
			expect(issues[0]?.message).toMatch(/"coercing-reader".*"verbatim-reader"/);
		});

		it("boot when one of them declares nothing: an empty object holds no value", async () => {
			const empty = defineModule({ name: "empty-reader", configSchema: z.object({}) });
			const config = await bootAndRead([empty, coercing], resolved({ widget: { size: "3" } }));
			expect(config.widget).toEqual({ size: 3 });
		});

		it("boot when they make the same value of it", async () => {
			const alsoCoercing = defineModule({
				name: "also-coercing-reader",
				configSchema: z.object({ widget: z.object({ size: z.coerce.number() }) }),
			});
			const config = await bootAndRead(
				[coercing, alsoCoercing],
				resolved({ widget: { size: "3" } }),
			);
			expect(config.widget).toEqual({ size: 3 });
		});
	});

	it("keeps what a module's configSchema does not declare under the keys it does", async () => {
		const reader = defineModule({
			name: "partial-reader",
			configSchema: z.object({ widget: z.object({ size: z.coerce.number() }) }),
		});
		const config = await bootAndRead([reader], resolved({ widget: { size: "3", note: "kept" } }));
		expect(config.widget).toEqual({ size: 3, note: "kept" });
	});
});

describe("a loaded module's section is never stripped", () => {
	it("is written back at a path under a section core declares", async () => {
		const seen: Record<string, unknown> = {};
		const config = await bootAndRead(
			[sectioned("fixture-widget", RetrySection, "oauth.fixtureWidget", seen)],
			resolved({ oauth: { ...makeValidCoreConfig().oauth, fixtureWidget: { retries: "3" } } }),
		);
		expect(seen["fixture-widget"]).toEqual({ retries: 3 });
		expect((config.oauth as Record<string, unknown>).fixtureWidget).toEqual({ retries: 3 });
	});

	it("is written back at a top-level path core does not declare", async () => {
		const config = await bootAndRead(
			[sectioned("fixture-section", RetrySection, undefined)],
			resolved({ "fixture-section": { retries: "3" } }),
		);
		expect(config["fixture-section"]).toEqual({ retries: 3 });
	});

	it("is laid over what is at its path, so a schema narrower than core's copy drops nothing", async () => {
		// A section schema that reads one key of a section core mirrors whole:
		// written back in place of the section, it would take every other key
		// from every module reading `config`.
		const session = makeValidAppConfig().session;
		const seen: Record<string, unknown> = {};
		const config = await bootAndRead(
			[sectioned("narrow-session", z.object({ name: z.string() }), "session", seen)],
			resolved({ session }),
		);
		expect(seen["narrow-session"]).toEqual({ name: session.name });
		expect((config.session as Record<string, unknown>).secret).toBe(session.secret);
		expect(Object.keys(config.session as object).sort()).toEqual(Object.keys(session).sort());
	});

	it("writes back what the schema makes of an absent section, and nothing when that is undefined", async () => {
		const config = await bootAndRead(
			[
				sectioned("defaulted", RetrySection.default({ retries: 7 }), undefined),
				sectioned("optional", RetrySection.optional(), "fixture.optional"),
			],
			resolved(),
		);
		expect(config.defaulted).toEqual({ retries: 7 });
		expect(Object.hasOwn(config, "fixture")).toBe(false);
	});

	it("refuses a section it cannot write back, naming the path that is in the way", async () => {
		const err = await bootRefused(
			[sectioned("under-a-scalar", RetrySection.default({ retries: 1 }), "legacy.fixture")],
			resolved({ legacy: 5 }),
		);
		expect(err.reason).toBe("config-validation-failed");
		expect(err.message).toMatch(/legacy\.fixture: /);
		expect(err.message).toMatch(/legacy holds a number, not an object/);
	});

	it("writes into an object without a prototype, keeping it one", async () => {
		const fixture = Object.assign(Object.create(null) as Record<string, unknown>, { other: 1 });
		const config = await bootAndRead(
			[sectioned("into-null-prototype", RetrySection, "fixture.inner")],
			resolved({ fixture: Object.assign(fixture, { inner: { retries: "2" } }) }),
		);
		const written = config.fixture as Record<string, unknown>;
		expect(Object.getPrototypeOf(written)).toBeNull();
		expect(written.other).toBe(1);
		expect(written.inner).toEqual({ retries: 2 });
	});

	it.each([
		["null", null, "null"],
		["a list", ["x"], "a list"],
		["an instance", new URL("https://idp.example/"), "an object that is not plain data"],
	])(
		"names what stands in the way by its kind, never its value: %s",
		async (_label, obstacle, kind) => {
			// The value there may be a secret; what the operator needs is where,
			// and what kind of thing, took the section's place.
			const err = await bootRefused(
				[sectioned("under-it", RetrySection.default({ retries: 1 }), "legacy.fixture")],
				resolved({ legacy: obstacle }),
			);
			expect(err.reason).toBe("config-validation-failed");
			expect(err.message).toMatch(
				new RegExp(`legacy\\.fixture: .*legacy holds ${kind}, not an object`),
			);
			expect(err.message).not.toMatch(/idp\.example/);
		},
	);
});

describe("a value a schema makes nothing of", () => {
	/** An environment variable exported empty: read as unset. */
	const blankIsUnset = <T extends z.ZodType>(schema: T) =>
		z.preprocess((value) => (value === "" ? undefined : value), schema.optional());

	it("is removed from the config slot, not left as it was written", async () => {
		const reader = defineModule({
			name: "blank-reader",
			configSchema: z.object({ widget: z.object({ note: blankIsUnset(z.string()) }) }),
		});
		const config = await bootAndRead([reader], resolved({ widget: { note: "", extra: "kept" } }));
		expect(config.widget).toEqual({ extra: "kept" });
		expect(Object.hasOwn(config.widget as object, "note")).toBe(false);
	});

	it("removes a section whose schema makes nothing of what is there", async () => {
		const seen: Record<string, unknown> = {};
		const config = await bootAndRead(
			[sectioned("blank-section", blankIsUnset(RetrySection), undefined, seen)],
			resolved({ "blank-section": "" }),
		);
		expect(seen["blank-section"]).toBeUndefined();
		expect(Object.hasOwn(config, "blank-section")).toBe(false);
	});
});

describe("a section nested in another module's", () => {
	const Outer = z.object({ level: z.coerce.number() });

	it("is read from what was written, parsed, and written back inside the outer section", async () => {
		// The outer schema keeps only `level`: were the inner section read from
		// its output, the inner module would be handed nothing.
		const seen: Record<string, unknown> = {};
		const modules = [
			sectioned("outer", Outer, "fixture", seen),
			sectioned("inner", RetrySection, "fixture.inner", seen),
		];
		const raw = resolved({ fixture: { level: "2", inner: { retries: "4" } } });
		const config = await bootAndRead(modules, raw);
		expect(seen.outer).toEqual({ level: 2 });
		expect(seen.inner).toEqual({ retries: 4 });
		expect(config.fixture).toEqual({ level: 2, inner: { retries: 4 } });
		// The order the modules are listed in decides nothing.
		expect(await bootAndRead([...modules].reverse(), raw)).toEqual(config);
	});

	it("is refused when the outer section's parsed value leaves no object to write it into", async () => {
		const err = await bootRefused(
			[
				sectioned("outer", z.object({ inner: z.string().optional() }).passthrough(), "fixture"),
				sectioned("inner", RetrySection.default({ retries: 1 }), "fixture.inner.deeper"),
			],
			resolved({ fixture: { inner: "a string" } }),
		);
		expect(err.reason).toBe("config-validation-failed");
		expect(err.message).toMatch(/fixture\.inner\.deeper: /);
	});

	it("may not share its path with another module's section", async () => {
		const err = await bootRefused(
			[
				sectioned("first", RetrySection, "fixture.shared"),
				sectioned("second", RetrySection, "fixture.shared"),
			],
			resolved({ fixture: { shared: { retries: 1 } } }),
		);
		expect(err.reason).toBe("module-section-path-invalid");
		expect(err.message).toMatch(
			/^Module "second" declares its section at "fixture\.shared": module "first"/,
		);
		expect(err.details).toEqual({
			reason: "module-section-path-invalid",
			module: "second",
			at: "fixture.shared",
			problem: 'module "first" declares its section there too, and a section has one owner',
		});
	});
});

describe("config_sections_ignored — a top-level section nobody owns (#728 B8)", () => {
	it("is kept, and named once in the log with every other one", async () => {
		const logger = recordingLogger();
		const reader = defineModule({
			name: "reader",
			configSchema: z.object({ readerSettings: z.object({}).passthrough() }),
		});
		const config = await bootAndRead(
			[reader, sectioned("fixture-section", RetrySection, undefined)],
			resolved({
				"fixture-section": { retries: 1 },
				readerSettings: {},
				redisRateLimiter: {},
				zeta: 1,
				typoSection: { enabled: true },
			}),
			logger,
		);
		expect(config.typoSection).toEqual({ enabled: true });
		expect(config.zeta).toBe(1);
		const ignored = logger.warn.mock.calls.filter(
			([, message]) => message === "config_sections_ignored",
		);
		expect(ignored).toEqual([[{ sections: ["typoSection", "zeta"] }, "config_sections_ignored"]]);
	});

	it("names the sections of a configuration handed as an object that is not plain data, by its own keys", async () => {
		// Boot's parse takes an instance as the configuration; its own keys are
		// the sections, and a key its prototype carries is not one.
		const logger = recordingLogger();
		const instance = Object.assign(
			Object.create({ inheritedSection: { enabled: true } }),
			resolved({ typoSection: { enabled: true } }),
		) as Record<string, unknown>;
		await bootAndRead([], instance, logger);
		expect(
			logger.warn.mock.calls.filter(([, message]) => message === "config_sections_ignored"),
		).toEqual([[{ sections: ["typoSection"] }, "config_sections_ignored"]]);
	});

	it("logs nothing when every section is owned", async () => {
		const logger = recordingLogger();
		await bootAndRead(
			[sectioned("fixture-section", RetrySection, "fixture.nested")],
			resolved({
				fixture: { nested: { retries: 1 } },
			}),
			logger,
		);
		expect(
			logger.warn.mock.calls.filter(([, message]) => message === "config_sections_ignored"),
		).toEqual([]);
	});
});
