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
 * `core.deployment.mode` and the expected session requirements at
 * `core.sessionRequirements.expected`, read from core's own `reference.conf`
 * resolved under an environment, as a composition root layers it. The paths
 * they moved from refuse boot naming the new one, and `DEPLOYMENT_MODE`,
 * renamed `CORE_DEPLOYMENT_MODE`, refuses boot unless the new name carries
 * the same value.
 */

import { fileURLToPath } from "node:url";
import { parseFile, parseString } from "@o3co/ts.hocon";
import { describe, expect, it, vi } from "vitest";
import { createApp } from "#/boot/create-app.mjs";
import { type AppHandle, BootError, type BootstrapMap } from "#/boot/types.mjs";
import { coreReference } from "#/config/references.mjs";
import type { Logger } from "#/logging/Logger.mjs";
import { makeValidCoreConfig } from "#/testing/fixtures/valid-config.mjs";

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

	it("refuses sessionRequirements.expected, naming core.sessionRequirements.expected", async () => {
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
		expect(err.message).not.toContain("environment variable CORE_SESSION_REQUIREMENTS_EXPECTED");
	});
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
