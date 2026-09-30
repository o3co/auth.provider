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
import { describe, expect, it } from "vitest";
import { createApp } from "#/boot/create-app.mjs";
import { type AppHandle, BootError, type BootstrapMap } from "#/boot/types.mjs";
import { coreReference } from "#/config/references.mjs";
import { makeValidCoreConfig } from "#/testing/fixtures/valid-config.mjs";

/** The sections core's reference sets that these tests read. */
const READ = ["core", "renamed-variables"] as const;

/** Core's valid configuration, under `operator` HOCON and core's own `reference.conf`, resolved under `env`. */
function resolved(env: Record<string, string>, operator = ""): Record<string, unknown> {
	const reference = parseFile(fileURLToPath(coreReference()), {
		env: { OAUTH_JWT_ISSUER: "https://auth.test", ...env },
	}).toObject() as Record<string, unknown>;
	const layers = parseString(operator, { env }).toObject() as Record<string, unknown>;
	return {
		...makeValidCoreConfig(),
		...Object.fromEntries(READ.map((section) => [section, reference[section]])),
		...layers,
	};
}

const bootstrap = (config: Record<string, unknown>): BootstrapMap =>
	({ config: config as never, pathResolver: (s: string) => s }) as BootstrapMap;

/** Boots no module over the configuration resolved under `env`. */
const boot = (env: Record<string, string>, operator = ""): Promise<AppHandle> =>
	createApp({ modules: [], bootstrapComponents: bootstrap(resolved(env, operator)) });

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

		expect(err.reason).toBe("config-path-relocated");
		expect(err.details).toMatchObject({
			relocated: [
				{
					module: "core",
					from: "sessionRequirements.expected",
					to: "core.sessionRequirements.expected",
				},
			],
		});
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
