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
 * Core's own settings, in its section `core`: the replica count at
 * `core.deployment.mode`, the expected session requirements at
 * `core.sessionRequirements.expected` and the token-binding settings at
 * `core.tokenBinding`, read from core's own `reference.conf` resolved under
 * an environment, as a composition root layers it. The paths they moved from
 * refuse boot naming the new one, and a variable renamed with them
 * (`DEPLOYMENT_MODE`, `OAUTH_TOKEN_BINDING_*`) refuses boot unless the new
 * name carries the same value.
 */

import { fileURLToPath } from "node:url";
import { parseFile, parseString } from "@o3co/ts.hocon";
import { describe, expect, it, vi } from "vitest";
import { createApp } from "#/boot/create-app.mjs";
import { type AppHandle, BootError, type BootstrapMap } from "#/boot/types.mjs";
import { AppConfigSchema } from "#/config/application.schema.mjs";
import { CORE_RELOCATIONS } from "#/config/core-relocations.mjs";
import { coreReference } from "#/config/references.mjs";
import { RENAMED_VARIABLES_SECTION } from "#/config/removed-keys.mjs";
import { jwksModule } from "#/jwks/module.mjs";
import { createSymmetricKeyStore } from "#/keys/KeyStore.mjs";
import type { Logger } from "#/logging/Logger.mjs";
import { resolveTokenBindingSettings } from "#/middleware/tokenBinding.mjs";
import { defineModule } from "#/modules/manifest/index.mjs";
import { makeValidAppConfig, makeValidCoreConfig } from "#/testing/fixtures/valid-config.mjs";
import { renamedVariableCaptures } from "#/testing/renamedVariables.mjs";

/** The sections core's reference sets that these tests read: core's own, the JWKS module's, and the captures. */
const READ = ["core", "jwks", "renamed-variables"] as const;

/**
 * Core's valid configuration, with `operator` HOCON over core's own
 * `reference.conf`, resolved under `env`: the sections in `READ`, and every
 * one the operator writes.
 */
function resolved(env: Record<string, string>, operator = ""): Record<string, unknown> {
	const own = parseString(operator, { env });
	const layered = own
		.withFallback(
			parseFile(fileURLToPath(coreReference()), {
				env: { OAUTH_JWT_ISSUER: "https://auth.test", ...env },
			}),
		)
		.toObject() as Record<string, unknown>;
	const sections = [...READ, ...Object.keys(own.toObject() as Record<string, unknown>)];
	return {
		...makeValidCoreConfig(),
		...Object.fromEntries(sections.map((section) => [section, layered[section]])),
	};
}

const bootstrap = (config: Record<string, unknown>, logger?: Logger): BootstrapMap =>
	({
		config: config as never,
		pathResolver: (s: string) => s,
		...(logger === undefined ? {} : { logger }),
	}) as BootstrapMap;

/** Boots no module over the configuration resolved under `env`, logging to `logger`. */
const boot = (env: Record<string, string>, operator = "", logger?: Logger): Promise<AppHandle> =>
	createApp({ modules: [], bootstrapComponents: bootstrap(resolved(env, operator), logger) });

/** A logger that records its warnings. */
const recordingLogger = (): Logger & { readonly warn: ReturnType<typeof vi.fn> } =>
	({
		trace: vi.fn(),
		debug: vi.fn(),
		info: vi.fn(),
		warn: vi.fn(),
		error: vi.fn(),
		fatal: vi.fn(),
	}) as unknown as Logger & { readonly warn: ReturnType<typeof vi.fn> };

/** What `createApp` refused with, or a failure when it booted. */
async function refusal(promise: Promise<AppHandle>): Promise<BootError> {
	try {
		const handle = await promise;
		await handle.dispose();
	} catch (err) {
		expect(err).toBeInstanceOf(BootError);
		return err as BootError;
	}
	return expect.fail("boot should have been refused");
}

/** The replica count boot filled the `deploymentMode` slot with. */
async function modeOf(env: Record<string, string>): Promise<unknown> {
	const handle = await boot(env);
	const mode = handle.components.deploymentMode;
	await handle.dispose();
	return mode;
}

describe("core's own settings, under core {}", () => {
	it.each(["single", "multi"])(
		"fills the deploymentMode slot from core.deployment.mode, which CORE_DEPLOYMENT_MODE=%s sets",
		async (mode) => {
			expect(await modeOf({ CORE_DEPLOYMENT_MODE: mode })).toBe(mode);
		},
	);

	it("fills it unset when nothing sets core.deployment.mode", async () => {
		expect(await modeOf({})).toBe("unset");
	});

	it("compares core.sessionRequirements.expected with what registered, naming the key", async () => {
		const err = await refusal(boot({}, 'core.sessionRequirements.expected = ["risk"]\n'));

		expect(err.reason).toBe("session-requirement-missing");
		expect(err.details).toMatchObject({
			configKey: "core.sessionRequirements.expected",
			missing: ["risk"],
		});
		expect(err.message).toContain("core.sessionRequirements.expected");
	});
});

describe("the paths core's settings moved from", () => {
	it("refuses deployment.mode, naming core.deployment.mode and the variable bound to it", async () => {
		const err = await refusal(boot({}, 'deployment.mode = "multi"\n'));

		expect(err.details).toEqual({
			reason: "config-path-relocated",
			relocated: [
				{
					module: "core",
					from: "deployment.mode",
					to: "core.deployment.mode",
					environmentVariable: "CORE_DEPLOYMENT_MODE",
				},
			],
		});
	});

	it("refuses sessionRequirements.expected, naming core.sessionRequirements.expected and no variable", async () => {
		const err = await refusal(boot({}, "sessionRequirements.expected = []\n"));

		expect(err.details).toEqual({
			reason: "config-path-relocated",
			relocated: [
				{
					module: "core",
					from: "sessionRequirements.expected",
					to: "core.sessionRequirements.expected",
				},
			],
		});
		expect(err.message).not.toMatch(/\(environment variable [A-Z0-9_]+\)/);
	});

	it.each([
		['deployment = "old-value-5e2d"', "deployment", "core.deployment"],
		["deployment.other = 1", "deployment.other", "core.deployment.other"],
	])("refuses %s, naming %s's new path and no variable", async (hocon, from, to) => {
		const err = await refusal(boot({}, `${hocon}\n`));

		expect(err.details).toEqual({
			reason: "config-path-relocated",
			relocated: [{ module: "core", from, to }],
		});
		expect(err.message).not.toMatch(/\(environment variable [A-Z0-9_]+\)/);
		expect(err.message).not.toContain("old-value-5e2d");
	});
});

describe("core's own section, strict", () => {
	it.each([
		['core.deploymnet.mode = "multi-5e2d"', "deploymnet", "multi-5e2d"],
		['core.sessionRequirement.expected = ["mfa-7c1b"]', "sessionRequirement", "mfa-7c1b"],
		['core.deployment.mdoe = "multi-5e2d"', "mdoe", "multi-5e2d"],
		['core.sessionRequirements.expcted = ["mfa-7c1b"]', "expcted", "mfa-7c1b"],
	])("refuses %s, naming the key %s and never its value", async (hocon, key, value) => {
		const err = await refusal(boot({}, `${hocon}\n`));

		expect(err.reason).toBe("config-validation-failed");
		expect(err.message).toContain(`"${key}"`);
		expect(err.message).not.toContain(value);
		expect(JSON.stringify(err.details)).not.toContain(value);
	});
});

describe("core.declaredAbsent, the slots a composition runs without on purpose", () => {
	it("reads a list of slot names, which no variable sets", async () => {
		const handle = await boot({}, 'core.declaredAbsent = ["auditSink"]\n');
		const config = handle.components.config as { core?: { declaredAbsent?: unknown } };
		expect(config.core?.declaredAbsent).toEqual(["auditSink"]);
		await handle.dispose();
	});

	it("ships none: core's reference.conf declares nothing absent", () => {
		const reference = parseFile(fileURLToPath(coreReference()), {
			env: { OAUTH_JWT_ISSUER: "https://auth.test" },
		}).toObject() as { core?: { declaredAbsent?: unknown } };
		expect(reference.core?.declaredAbsent).toBeUndefined();
	});

	it.each([
		['core.declaredAbsent = "auditSink"', "a name that is not in a list"],
		['core.declaredAbsent = [""]', "an empty name"],
	])("refuses %s (%s), naming core.declaredAbsent", async (hocon) => {
		const err = await refusal(boot({}, `${hocon}\n`));

		expect(err.reason).toBe("config-validation-failed");
		expect(err.message).toContain("core.declaredAbsent");
	});
});

describe("the federations, under core.federations", () => {
	it("reads each federation written there, its switches as the strings an environment variable carries", async () => {
		const handle = await boot(
			{},
			'core.federations.upstream { enabled = "false", type = "oidc", trustUpstreamAmr = "true" }\n',
		);
		const config = handle.components.config as {
			core?: { federations?: Record<string, Record<string, unknown>> };
		};
		expect(config.core?.federations?.upstream).toEqual({
			enabled: false,
			type: "oidc",
			trustUpstreamAmr: true,
		});
		await handle.dispose();
	});

	it("ships an empty map there, and nothing at the top level", () => {
		const reference = parseFile(fileURLToPath(coreReference()), {
			env: { OAUTH_JWT_ISSUER: "https://auth.test" },
		}).toObject() as { core?: { federations?: unknown }; federations?: unknown };
		expect(reference.core?.federations).toEqual({});
		expect(reference).not.toHaveProperty("federations");
	});

	it("refuses an enabled federation without the stores it needs, naming it under core.federations", async () => {
		const err = await refusal(boot({}, "core.federations.upstream.enabled = true\n"));

		expect(err.message).toContain("core.federations.upstream");
	});

	it("refuses federations at the top level, naming each key's path under core.federations and its variable", async () => {
		const err = await refusal(
			boot(
				{},
				'federations.google.enabled = true\nfederations.google.clientId = "old-value-5e2d"\n',
			),
		);

		expect(err.details).toEqual({
			reason: "config-path-relocated",
			relocated: [
				{
					module: "core",
					from: "federations.google.enabled",
					to: "core.federations.google.enabled",
					environmentVariable: "CORE_FEDERATIONS_GOOGLE_ENABLED",
				},
				{
					module: "core",
					from: "federations.google.clientId",
					to: "core.federations.google.clientId",
					environmentVariable: "CORE_FEDERATIONS_GOOGLE_CLIENT_ID",
				},
			],
		});
		expect(err.message).not.toContain("old-value-5e2d");
	});
});

describe("a root that parses its resolved configuration with AppConfigSchema before boot", () => {
	/**
	 * `operator` HOCON over core's own `reference.conf` and the fixture's
	 * sections, parsed with `AppConfigSchema`, with the captures the
	 * resolution saw added back, as such a root must.
	 */
	const preParsed = (operator: string): Record<string, unknown> => {
		const own = parseString(operator, {});
		const layered = own
			.withFallback(
				parseFile(fileURLToPath(coreReference()), {
					env: { OAUTH_JWT_ISSUER: "https://auth.test" },
				}),
			)
			.toObject() as Record<string, unknown>;
		const sections = [...READ, ...Object.keys(own.toObject() as Record<string, unknown>)];
		const parsed = AppConfigSchema.parse({
			...makeValidAppConfig(),
			...Object.fromEntries(sections.map((section) => [section, layered[section]])),
		}) as Record<string, unknown>;
		return {
			...parsed,
			[RENAMED_VARIABLES_SECTION]: renamedVariableCaptures({
				modules: [],
				core: CORE_RELOCATIONS,
				env: {},
			}),
		};
	};

	/** The key store the jwks module requires. */
	const keyStoreModule = defineModule({
		name: "test:key-store",
		provides: { keyStore: () => createSymmetricKeyStore("core-section-test-secret-for-jwks!!") },
	});

	it.each([
		['deployment.mode = "multi"', [], "deployment.mode"],
		['sessionRequirements.expected = ["mfa"]', [], "sessionRequirements.expected"],
		[
			'oauth.tokenBinding.dispatch-policy = "strict-mutual-exclusion"',
			[],
			"oauth.tokenBinding.dispatch-policy",
		],
		['oauth.jwt.jwksPath = "/keys/jwks.json"', [jwksModule, keyStoreModule], "oauth.jwt.jwksPath"],
		["oauth.jwt.jwksCacheMaxAge = 60", [jwksModule, keyStoreModule], "oauth.jwt.jwksCacheMaxAge"],
	] as const)(
		"is refused for %s as relocated, the parse keeping the old path",
		async (hocon, modules, from) => {
			const err = await refusal(
				createApp({ modules, bootstrapComponents: bootstrap(preParsed(`${hocon}\n`)) }),
			);

			expect(err.reason).toBe("config-path-relocated");
			expect(err.details).toMatchObject({ relocated: [{ from }] });
		},
	);
});

describe("the JWKS module's section, shipped in core's reference.conf, in a composition without the module", () => {
	/** The sections the boot named as nothing owns, once per boot. */
	const ignoredBy = async (env: Record<string, string>, operator = ""): Promise<unknown[]> => {
		const logger = recordingLogger();
		const handle = await boot(env, operator, logger);
		await handle.dispose();
		return logger.warn.mock.calls
			.filter(([, message]) => message === "config_sections_ignored")
			.map(([fields]) => fields);
	};

	it("is named as no ignored section while its variables are unset", async () => {
		expect(await ignoredBy({})).toEqual([]);
	});

	it("is named once as ignored when the operator writes jwks.path", async () => {
		expect(await ignoredBy({}, 'jwks.path = "/keys/jwks.json"\n')).toEqual([
			{ sections: ["jwks"] },
		]);
	});

	it("is named once as ignored when JWKS_PATH is set", async () => {
		expect(await ignoredBy({ JWKS_PATH: "/keys/jwks.json" })).toEqual([{ sections: ["jwks"] }]);
	});
});

describe("DEPLOYMENT_MODE, renamed CORE_DEPLOYMENT_MODE", () => {
	it("set alone: refused, naming the new variable and core.deployment.mode", async () => {
		const err = await refusal(boot({ DEPLOYMENT_MODE: "multi" }));

		expect(err.details).toEqual({
			reason: "environment-variable-renamed",
			renamed: [
				{
					module: "core",
					from: "DEPLOYMENT_MODE",
					to: "CORE_DEPLOYMENT_MODE",
					path: "core.deployment.mode",
					state: "unset",
				},
			],
		});
	});

	it("set beside CORE_DEPLOYMENT_MODE at a different value: refused, naming neither value", async () => {
		const err = await refusal(
			boot({ DEPLOYMENT_MODE: "old-mode-5e2d", CORE_DEPLOYMENT_MODE: "new-mode-c81a" }),
		);

		expect(err.details).toMatchObject({
			renamed: [{ from: "DEPLOYMENT_MODE", to: "CORE_DEPLOYMENT_MODE", state: "different" }],
		});
		expect(err.message).not.toContain("old-mode-5e2d");
		expect(err.message).not.toContain("new-mode-c81a");
	});

	it("set beside CORE_DEPLOYMENT_MODE at the same value: boots with that mode", async () => {
		expect(await modeOf({ DEPLOYMENT_MODE: "multi", CORE_DEPLOYMENT_MODE: "multi" })).toBe("multi");
	});
});

describe("the token-binding settings, under core.tokenBinding", () => {
	/** The token-binding settings of the configuration boot parsed, as core reads them. */
	async function settingsOf(env: Record<string, string>, operator = "") {
		const handle = await boot(env, operator);
		const settings = resolveTokenBindingSettings(handle.components.config);
		await handle.dispose();
		return settings;
	}

	it("reads intent-explicit and no confidential-client binding when nothing sets them", async () => {
		expect(await settingsOf({})).toEqual({
			dispatchPolicy: "intent-explicit",
			bindConfidentialClientRefreshTokens: false,
		});
	});

	it("reads what CORE_TOKEN_BINDING_DISPATCH_POLICY and CORE_TOKEN_BINDING_BIND_CONFIDENTIAL_CLIENT_REFRESH_TOKENS set", async () => {
		expect(
			await settingsOf({
				CORE_TOKEN_BINDING_DISPATCH_POLICY: "strict-mutual-exclusion",
				CORE_TOKEN_BINDING_BIND_CONFIDENTIAL_CLIENT_REFRESH_TOKENS: "true",
			}),
		).toEqual({
			dispatchPolicy: "strict-mutual-exclusion",
			bindConfidentialClientRefreshTokens: true,
		});
	});

	it("reads what core.tokenBinding says in a layer", async () => {
		expect(
			await settingsOf(
				{},
				'core.tokenBinding { dispatchPolicy = "strict-mutual-exclusion", bindConfidentialClientRefreshTokens = true }\n',
			),
		).toEqual({
			dispatchPolicy: "strict-mutual-exclusion",
			bindConfidentialClientRefreshTokens: true,
		});
	});

	it("refuses a key core.tokenBinding does not declare, naming it and never its value", async () => {
		const err = await refusal(boot({}, 'core.tokenBinding.dispatchPolcy = "strict-5e2d"\n'));

		expect(err.reason).toBe("config-validation-failed");
		expect(err.message).toContain('"dispatchPolcy"');
		expect(err.message).not.toContain("strict-5e2d");
	});
});

describe("the paths the token-binding settings moved from", () => {
	it.each([
		[
			'oauth.tokenBinding.dispatch-policy = "strict-mutual-exclusion"',
			"oauth.tokenBinding.dispatch-policy",
			"core.tokenBinding.dispatchPolicy",
			"CORE_TOKEN_BINDING_DISPATCH_POLICY",
		],
		[
			"oauth.tokenBinding.bindConfidentialClientRefreshTokens = true",
			"oauth.tokenBinding.bindConfidentialClientRefreshTokens",
			"core.tokenBinding.bindConfidentialClientRefreshTokens",
			"CORE_TOKEN_BINDING_BIND_CONFIDENTIAL_CLIENT_REFRESH_TOKENS",
		],
	])("refuses %s, naming %s's new path and its variable", async (hocon, from, to, variable) => {
		const err = await refusal(boot({}, `${hocon}\n`));

		expect(err.details).toEqual({
			reason: "config-path-relocated",
			relocated: [{ module: "core", from, to, environmentVariable: variable }],
		});
	});

	it("refuses another key under oauth.tokenBinding, naming its path under core.tokenBinding and no variable", async () => {
		const err = await refusal(boot({}, 'oauth.tokenBinding.other = "old-value-5e2d"\n'));

		expect(err.details).toEqual({
			reason: "config-path-relocated",
			relocated: [
				{ module: "core", from: "oauth.tokenBinding.other", to: "core.tokenBinding.other" },
			],
		});
		expect(err.message).not.toContain("old-value-5e2d");
	});
});

describe("the token-binding variables, renamed after their paths under core", () => {
	it.each([
		[
			"OAUTH_TOKEN_BINDING_DISPATCH_POLICY",
			"CORE_TOKEN_BINDING_DISPATCH_POLICY",
			"core.tokenBinding.dispatchPolicy",
		],
		[
			"OAUTH_TOKEN_BINDING_BIND_CONFIDENTIAL_CLIENT_REFRESH_TOKENS",
			"CORE_TOKEN_BINDING_BIND_CONFIDENTIAL_CLIENT_REFRESH_TOKENS",
			"core.tokenBinding.bindConfidentialClientRefreshTokens",
		],
	])("%s set alone: refused, naming %s and its path", async (from, to, path) => {
		const err = await refusal(boot({ [from]: "true" }));

		expect(err.details).toEqual({
			reason: "environment-variable-renamed",
			renamed: [{ module: "core", from, to, path, state: "unset" }],
		});
	});

	it("set beside the new name at a different value: refused, naming neither value", async () => {
		const err = await refusal(
			boot({
				OAUTH_TOKEN_BINDING_DISPATCH_POLICY: "old-policy-5e2d",
				CORE_TOKEN_BINDING_DISPATCH_POLICY: "new-policy-c81a",
			}),
		);

		expect(err.details).toMatchObject({
			renamed: [
				{
					from: "OAUTH_TOKEN_BINDING_DISPATCH_POLICY",
					to: "CORE_TOKEN_BINDING_DISPATCH_POLICY",
					state: "different",
				},
			],
		});
		expect(err.message).not.toContain("old-policy-5e2d");
		expect(err.message).not.toContain("new-policy-c81a");
	});

	it("set beside the new name at the same value: boots with that value", async () => {
		const handle = await boot({
			OAUTH_TOKEN_BINDING_DISPATCH_POLICY: "strict-mutual-exclusion",
			CORE_TOKEN_BINDING_DISPATCH_POLICY: "strict-mutual-exclusion",
			OAUTH_TOKEN_BINDING_BIND_CONFIDENTIAL_CLIENT_REFRESH_TOKENS: "true",
			CORE_TOKEN_BINDING_BIND_CONFIDENTIAL_CLIENT_REFRESH_TOKENS: "true",
		});
		const settings = resolveTokenBindingSettings(handle.components.config);
		await handle.dispose();

		expect(settings).toEqual({
			dispatchPolicy: "strict-mutual-exclusion",
			bindConfidentialClientRefreshTokens: true,
		});
	});
});
