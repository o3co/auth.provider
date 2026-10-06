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
 * Boot's one composed parse. A composition root hands `createApp` the
 * configuration it resolved — never parsed first — and boot parses it once:
 * with core's base (`CoreConfigSchema`, core's sections alone), laid over
 * what was written so nothing is stripped; then each module's section at its
 * name, over the base's output, written back there. A top-level section
 * nobody owns is kept as written, validated by nothing, and named once in
 * the log.
 */

import { describe, expect, it, vi } from "vitest";
import { z } from "zod";
import type { AppConfig } from "../../config/application.schema.mjs";
import type { Logger } from "../../logging/Logger.mjs";
import { defineModule } from "../../modules/manifest/index.mjs";
import type { Module } from "../../modules/manifest/module-spec.mjs";
import { makeValidCoreConfig } from "../../testing/fixtures/valid-config.mjs";
import { createApp } from "../create-app.mjs";
import type { BootstrapMap } from "../types.mjs";
import { BootError } from "../types.mjs";
import { validateManifests } from "../validate-manifests.mjs";

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

/**
 * The fixture's configuration less the oauth package's grant switches
 * (`oauth-session`, `oauth-authorization`): no module here reads them, so
 * boot would name them as ignored.
 */
function withoutGrantSwitches(): Record<string, unknown> {
	const {
		"oauth-session": _session,
		"oauth-authorization": _authorization,
		...config
	} = makeValidCoreConfig();
	return config;
}

/** A resolved configuration: core's sections, plus whatever `extra` adds at the top. */
const resolved = (extra: Record<string, unknown> = {}): Record<string, unknown> => ({
	...withoutGrantSwitches(),
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

/** A module whose section, at its name, is `schema`, recording what its factory was handed. */
function sectioned(name: string, schema: z.ZodType, seen: Record<string, unknown> = {}): Module {
	return defineModule({
		name,
		section: { schema },
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

describe("one composed parse over core's base", () => {
	it("keeps a section no loaded module owns as written: core's base coerces nothing in it", async () => {
		const config = await bootAndRead(
			[],
			resolved({ webauthn: { challengeTtlMs: "120000", rpId: "example.com" } }),
		);
		expect(config.webauthn).toEqual({ challengeTtlMs: "120000", rpId: "example.com" });
	});

	it("refuses a value core's base refuses, naming the operator's path", async () => {
		const err = await bootRefused(
			[],
			resolved({ core: { ...makeValidCoreConfig().core, deployment: { mode: "loud" } } }),
		);
		expect(err.reason).toBe("config-validation-failed");
		expect(err.message).toMatch(/core\.deployment\.mode: /);
	});

	it.each([
		[
			"an async refinement",
			z.object({ size: z.number() }).refine(async () => true),
			/could not be parsed synchronously/,
		],
		[
			"a transform that throws",
			z.object({
				size: z.number().transform((): number => {
					throw new Error("the widget broke");
				}),
			}),
			/the widget broke/,
		],
	])(
		"refuses a module's section schema that throws instead of answering — %s — naming its section",
		async (_label, schema, cause) => {
			const err = await bootRefused(
				[sectioned("throwing-reader", schema)],
				resolved({ "throwing-reader": { size: 3 } }),
			);
			expect(err.reason).toBe("config-validation-failed");
			expect(err.message).toMatch(/throwing-reader: /);
			expect(err.message).toMatch(cause);
			expect(err.details).toMatchObject({
				modules: [{ module: "throwing-reader", schemaPath: "throwing-reader" }],
			});
		},
	);

	it("refuses a configuration a read of which throws, rather than letting the error escape", async () => {
		// A hand-built configuration with a getter that throws: core's own parse
		// reads it.
		const nonce = {
			get maxLength(): number {
				throw new Error("the length getter broke");
			},
		};
		const err = await bootRefused(
			[],
			resolved({ oauth: { ...makeValidCoreConfig().oauth, nonce } }),
		);
		expect(err.reason).toBe("config-validation-failed");
		expect(err.message).toMatch(/core's configuration schema threw instead of answering/);
		expect(err.message).toMatch(/the length getter broke/);
	});

	it("names the configuration itself when it is not an object, when core declares no renamed variable", () => {
		// Core's own renamed variables are judged before the parse, and a value
		// that is no object captures none: validated here without them.
		let err: unknown;
		try {
			validateManifests({
				modules: [],
				bootstrapComponents: {
					config: "http.port = 3000",
					pathResolver: (s: string) => s,
				} as unknown as BootstrapMap,
				core: {},
			});
		} catch (caught) {
			err = caught;
		}
		expect(err).toBeInstanceOf(BootError);
		expect((err as BootError).reason).toBe("config-validation-failed");
		expect((err as BootError).message).toMatch(/: \(the configuration\): /);
	});

	it("names every refused path in the message", async () => {
		const err = await bootRefused(
			[],
			resolved({
				oauth: { ...makeValidCoreConfig().oauth, nonce: { maxLength: "not-a-number" } },
				core: { ...makeValidCoreConfig().core, deployment: { mode: "loud" } },
			}),
		);
		expect(err.reason).toBe("config-validation-failed");
		expect(err.message).toMatch(/oauth\.nonce\.maxLength: /);
		expect(err.message).toMatch(/core\.deployment\.mode: /);
	});

	it("keeps a key no schema declares under a section core declares", async () => {
		const config = await bootAndRead(
			[],
			resolved({ oauth: { ...makeValidCoreConfig().oauth, extra: "kept" } }),
		);
		expect((config.oauth as Record<string, unknown>).extra).toBe("kept");
	});

	it("hands a module's section the base's output where the base declares the section: an environment string arrives coerced", async () => {
		const seen: Record<string, unknown> = {};
		const config = await bootAndRead(
			[sectioned("oauth", z.object({ nonce: z.object({ maxLength: z.number() }) }), seen)],
			resolved({ oauth: { ...makeValidCoreConfig().oauth, nonce: { maxLength: "128" } } }),
		);
		expect(seen.oauth).toEqual({ nonce: { maxLength: 128 } });
		expect((config.oauth as { nonce?: unknown }).nonce).toEqual({ maxLength: 128 });
	});

	it("hands a module's section what was written where the base does not declare it: the module's own schema reads an environment string", async () => {
		const err = await bootRefused(
			[sectioned("webauthn", z.object({ challengeTtlMs: z.number() }))],
			resolved({ webauthn: { challengeTtlMs: "120000" } }),
		);
		expect(err.reason).toBe("config-validation-failed");
		expect(err.message).toMatch(/webauthn\.challengeTtlMs: /);

		const seen: Record<string, unknown> = {};
		const config = await bootAndRead(
			[sectioned("webauthn", z.object({ challengeTtlMs: z.coerce.number() }), seen)],
			resolved({ webauthn: { challengeTtlMs: "120000" } }),
		);
		expect(seen.webauthn).toEqual({ challengeTtlMs: 120000 });
		expect(config.webauthn).toEqual({ challengeTtlMs: 120000 });
	});

	it("reports only the base's refusals when the base refuses, not a module's section reading what the base would have coerced", async () => {
		// Run over what was written, a section's schema would refuse the
		// environment string the base reads as a number: an error nobody made.
		const err = await bootRefused(
			[sectioned("oauth", z.object({ nonce: z.object({ maxLength: z.number() }) }))],
			resolved({
				oauth: { ...makeValidCoreConfig().oauth, nonce: { maxLength: "128" } },
				core: { ...makeValidCoreConfig().core, deployment: { mode: "loud" } },
			}),
		);
		expect(err.reason).toBe("config-validation-failed");
		expect(err.message).toMatch(/core\.deployment\.mode: /);
		expect(err.message).not.toMatch(/oauth\.nonce\.maxLength/);
		expect(
			(err.details as unknown as { issues: { path: PropertyKey[] }[] }).issues.map((issue) =>
				issue.path.join("."),
			),
		).toEqual(["core.deployment.mode"]);
	});

	it("keeps what a module's section schema does not declare under the keys it does", async () => {
		const seen: Record<string, unknown> = {};
		const config = await bootAndRead(
			[sectioned("widget", z.object({ size: z.coerce.number() }), seen)],
			resolved({ widget: { size: "3", note: "kept" } }),
		);
		expect(seen.widget).toEqual({ size: 3 });
		expect(config.widget).toEqual({ size: 3, note: "kept" });
	});
});

describe("a module rewrites nothing outside its own section", () => {
	/** Under `multi`, the replica-safety guard refuses this module. */
	const replicaUnsafe = defineModule({
		name: "fixture-replica-unsafe",
		replicaSafety: { unsafe: true, reason: "state forks per replica" },
	});
	const multi = () =>
		resolved({ core: { ...makeValidCoreConfig().core, deployment: { mode: "multi" } } });

	it("refuses a manifest carrying a configSchema that would rewrite core's deployment mode", async () => {
		const rewriting = defineModule({
			name: "fixture-rewriting",
			configSchema: z.object({
				core: z.object({
					deployment: z.object({ mode: z.unknown().transform(() => "single") }),
				}),
			}),
		} as never);
		const err = await bootRefused([rewriting, replicaUnsafe], multi());
		expect(err.reason).toBe("module-section-path-invalid");
		expect(err.details).toMatchObject({ module: "fixture-rewriting" });
	});

	it.each([
		["core.deployment.mode", { core: { deployment: { mode: "single" } } }],
		[
			"core.sessionRequirements",
			{ core: { sessionRequirements: { expected: ["fixture-requirement"] } } },
		],
	])(
		"writes a section's output back at its name alone: %s stays as written",
		async (_label, output) => {
			const seen: Record<string, unknown> = {};
			const rewriting = sectioned(
				"fixture-rewriting",
				z.unknown().transform(() => output),
				seen,
			);
			const written = multi();
			const config = await bootAndRead([rewriting], written);
			expect(seen["fixture-rewriting"]).toEqual(output);
			expect(config["fixture-rewriting"]).toEqual(output);
			expect(config.core).toEqual(written.core);
		},
	);

	it("refuses a module named core, the one name whose section would be core's keys", async () => {
		const rewriting = sectioned(
			"core",
			z.unknown().transform(() => ({ deployment: { mode: "single" } })),
		);
		const err = await bootRefused([rewriting, replicaUnsafe], multi());
		expect(err.reason).toBe("module-section-path-invalid");
		expect(err.details).toMatchObject({ module: "core", at: "core" });
	});

	it("writes a section naming the issuer, from a module not named oauth, under its own name", async () => {
		const output = { oauth: { jwt: { issuer: "https://rewritten.example" } } };
		const config = await bootAndRead(
			[
				sectioned(
					"fixture-rewriting",
					z.unknown().transform(() => output),
				),
			],
			multi(),
		);
		expect(config["fixture-rewriting"]).toEqual(output);
		expect((config.oauth as { jwt?: unknown }).jwt).toEqual(makeValidCoreConfig().oauth.jwt);
	});

	it("still refuses a replica-unsafe module under multi when a section's output names single", async () => {
		const rewriting = sectioned(
			"fixture-rewriting",
			z.unknown().transform(() => ({ core: { deployment: { mode: "single" } } })),
		);
		const err = await bootRefused([rewriting, replicaUnsafe], multi());
		expect(err.reason).toBe("replica-unsafe-adapter");
	});
});

describe("a loaded module's section is never stripped", () => {
	it("is written back at a section core's base also declares", async () => {
		const seen: Record<string, unknown> = {};
		const config = await bootAndRead(
			[sectioned("oauth", z.object({ oidcMode: z.string() }), seen)],
			resolved({ oauth: { ...makeValidCoreConfig().oauth, nonce: { maxLength: "128" } } }),
		);
		expect(seen.oauth).toEqual({ oidcMode: makeValidCoreConfig().oauth.oidcMode });
		expect(config.oauth).toMatchObject({
			oidcMode: makeValidCoreConfig().oauth.oidcMode,
			jwt: makeValidCoreConfig().oauth.jwt,
			nonce: { maxLength: 128 },
		});
	});

	it("is written back at a top-level path core does not declare", async () => {
		const config = await bootAndRead(
			[sectioned("fixture-section", RetrySection)],
			resolved({ "fixture-section": { retries: "3" } }),
		);
		expect(config["fixture-section"]).toEqual({ retries: 3 });
	});

	it("is written back into a configuration handed over without a prototype, every other section kept", async () => {
		const config = Object.assign(Object.create(null) as Record<string, unknown>, {
			...resolved({ other: { kept: 1 }, "fixture-section": { retries: "2" } }),
		});
		const parsed = await bootAndRead([sectioned("fixture-section", RetrySection)], config);
		expect(parsed["fixture-section"]).toEqual({ retries: 2 });
		expect(parsed.other).toEqual({ kept: 1 });
		expect(parsed.core).toEqual(makeValidCoreConfig().core);
	});

	it("is laid over what is at its name, so a schema narrower than what is written drops nothing", async () => {
		// A section schema that reads one key of a section written whole:
		// written back in place of the section, it would take every other key
		// from every module reading `config`.
		const repositories = {
			client: { type: "yaml" },
			user: { type: "yaml" },
			code: { type: "memory" },
		};
		const seen: Record<string, unknown> = {};
		const config = await bootAndRead(
			[sectioned("repositories", z.object({ code: z.object({ type: z.string() }) }), seen)],
			resolved({ repositories }),
		);
		expect(seen.repositories).toEqual({ code: { type: repositories.code.type } });
		const written = config.repositories as Record<string, unknown>;
		expect(written.client).toEqual(repositories.client);
		expect(Object.keys(written).sort()).toEqual(Object.keys(repositories).sort());
	});

	it("writes back what the schema makes of an absent section, and nothing when that is undefined", async () => {
		const config = await bootAndRead(
			[
				sectioned("defaulted", RetrySection.default({ retries: 7 })),
				sectioned("optional", RetrySection.optional()),
			],
			resolved(),
		);
		expect(config.defaulted).toEqual({ retries: 7 });
		expect(Object.hasOwn(config, "optional")).toBe(false);
	});
});

describe("a value a schema makes nothing of", () => {
	/** An environment variable exported empty: read as unset. */
	const blankIsUnset = <T extends z.ZodType>(schema: T) =>
		z.preprocess((value) => (value === "" ? undefined : value), schema.optional());

	it("is removed from the config slot, not left as it was written", async () => {
		const config = await bootAndRead(
			[sectioned("widget", z.object({ note: blankIsUnset(z.string()) }))],
			resolved({ widget: { note: "", extra: "kept" } }),
		);
		expect(config.widget).toEqual({ extra: "kept" });
		expect(Object.hasOwn(config.widget as object, "note")).toBe(false);
	});

	it("removes a section whose schema makes nothing of what is there", async () => {
		const seen: Record<string, unknown> = {};
		const config = await bootAndRead(
			[sectioned("blank-section", blankIsUnset(RetrySection), seen)],
			resolved({ "blank-section": "" }),
		);
		expect(seen["blank-section"]).toBeUndefined();
		expect(Object.hasOwn(config, "blank-section")).toBe(false);
	});
});

describe("a section has one owner", () => {
	it("refuses two modules of one name: they would read one section", async () => {
		const err = await bootRefused(
			[sectioned("fixture-shared", RetrySection), sectioned("fixture-shared", RetrySection)],
			resolved({ "fixture-shared": { retries: 1 } }),
		);
		expect(err.reason).toBe("duplicate-module-name");
	});
});

describe("config_sections_ignored — a top-level section nobody owns", () => {
	it("is kept, and named once in the log with every other one", async () => {
		const logger = recordingLogger();
		const config = await bootAndRead(
			[
				sectioned("readerSettings", z.object({}).passthrough()),
				sectioned("fixture-section", RetrySection),
			],
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

	it("does not name a section that holds no key: it sets nothing, as a reference leaves one whose variables are unset", async () => {
		const logger = recordingLogger();
		const config = await bootAndRead(
			[],
			resolved({ emptySection: {}, typoSection: { enabled: true } }),
			logger,
		);
		expect(config.emptySection).toEqual({});
		expect(
			logger.warn.mock.calls.filter(([, message]) => message === "config_sections_ignored"),
		).toEqual([[{ sections: ["typoSection"] }, "config_sections_ignored"]]);
	});

	it("does not name a section that holds only empty sections: it sets nothing either", async () => {
		const logger = recordingLogger();
		await bootAndRead(
			[],
			resolved({ typoSection: { nested: {} }, listSection: [], valueSection: { key: 1 } }),
			logger,
		);
		expect(
			logger.warn.mock.calls.filter(([, message]) => message === "config_sections_ignored"),
		).toEqual([[{ sections: ["listSection", "valueSection"] }, "config_sections_ignored"]]);
	});

	it("names the sections of a configuration handed as an object that is not plain data, by its own keys", async () => {
		// Boot's parse takes an instance as the configuration; its own keys are
		// the sections, and a key its prototype carries is not one.
		// Validated without core's own renamed variables, whose captures an
		// instance would carry as a section of its own.
		const logger = recordingLogger();
		const { "renamed-variables": _captures, ...plain } = resolved({
			typoSection: { enabled: true },
		});
		const instance = Object.assign(
			Object.create({ inheritedSection: { enabled: true } }),
			plain,
		) as Record<string, unknown>;
		validateManifests({
			modules: [],
			bootstrapComponents: {
				config: instance,
				pathResolver: (s: string) => s,
				logger,
			} as unknown as BootstrapMap,
			core: {},
		});
		expect(
			logger.warn.mock.calls.filter(([, message]) => message === "config_sections_ignored"),
		).toEqual([[{ sections: ["typoSection"] }, "config_sections_ignored"]]);
	});

	it("logs nothing when every section is owned", async () => {
		const logger = recordingLogger();
		await bootAndRead(
			[sectioned("fixture", z.object({ nested: RetrySection }))],
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

describe("another package's section, its module not loaded", () => {
	// Core's base declares core's sections alone: a section another package's
	// module reads, or a path one moved from, is validated by that module when
	// it is loaded and by nothing when it is not. Kept as written, and named
	// as nothing loaded reads it. `cors` is the exception, refused whenever it
	// sets anything (core-section.test.mts).
	it.each([
		["webauthn", { userVerification: "optional", challengeTtlMs: "not-a-lifetime" }],
		["federation-grants", { enabled: "sometimes", maxExpiresIn: "not-a-duration" }],
		["oauth-session", { enabled: "sometimes" }],
		["oauth-authorization", { grants: { authorizationCode: { enabled: "x" } } }],
		["session", { loginPage: { url: "" }, secret: "moved" }],
		["session-store", { storage: { type: 42 }, maxAge: "0" }],
		["rateLimit", { login: { windowMs: 0 }, failMode: "sometimes" }],
		["endpoints", { login: { url: "/login" } }],
		["repositories", { client: { type: "yaml" } }],
		["audit", { sink: { type: "splunk-hec" } }],
		["core-rate-limiter-memory", { limits: { token: { limit: "0", windowSeconds: 1e13 } } }],
		["redis-rate-limiter", { keyPrefix: "{x}" }],
		["redis-consent-store", { keyPrefix: "tenant-a:consent:" }],
		["redis-federation-token-store", { encryptionMode: "optional", keyPrefix: "tenant-a:ft:" }],
		["core-federation-grant-store-memory", { tombstoneRetention: "not-a-duration" }],
		["redis-federation-grant-store", { keyPrefix: "{x}" }],
		["redis-federation-grant-intent-store", { keyPrefix: "{x}" }],
		["redis-mfa-factor-store", { keyPrefix: "t:mfaf:" }],
		["federationGrants", { enabled: "sometimes" }],
		["consentStore", { adapter: "postgres" }],
		["federationTokenStore", { type: "postgres" }],
		["federationGrantStore", { adapter: "postgres" }],
		["federationGrantIntentStore", { adapter: "postgres" }],
		["memoryRateLimiter", { maxBuckets: "many" }],
		["redisRateLimiter", { keyPrefix: "{x}" }],
		["redisConsentStore", { keyPrefix: "tenant-a:consent:" }],
		["redisDeviceCodeStore", { keyPrefix: "tenant-a:devauth:" }],
		["redisFederationTokenStore", { keyPrefix: "tenant-a:ft:" }],
		["redisFederationGrantStore", { keyPrefix: "{x}" }],
	] as const)(
		"boots with %s, whatever it holds, kept as written and named as ignored",
		async (section, written) => {
			const logger = recordingLogger();
			const config = await bootAndRead([], resolved({ [section]: written }), logger);
			expect(config[section]).toEqual(written);
			expect(
				logger.warn.mock.calls.filter(([, message]) => message === "config_sections_ignored"),
			).toEqual([[{ sections: [section] }, "config_sections_ignored"]]);
		},
	);

	it("is absent from the config slot when not written: core's base supplies no default for it", async () => {
		const config = await bootAndRead([], resolved());
		for (const section of ["webauthn", "federation-grants", "session-store", "cors", "audit"]) {
			expect(Object.hasOwn(config, section), section).toBe(false);
		}
	});
});
