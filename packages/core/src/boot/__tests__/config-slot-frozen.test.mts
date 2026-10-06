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
 * The `config` slot — the configuration stage 1 parsed — is one object every
 * module that requires it reads, and core reads it again after providers have
 * run (the stage-3 lifetime gate on `oauthTokenSettings`, the slots it holds
 * to declared absence, the app's settings). Boot hands it over as a frozen
 * copy of plain data: a module's write throws (`TypeError`, modules being
 * strict-mode code), so no module changes what another module or core reads,
 * and the host's own configuration object is left as the host made it.
 */

import { describe, expect, it } from "vitest";
import { defineModule, type Module } from "../../modules/manifest/index.mjs";
import { makeValidCoreConfig } from "../../testing/fixtures/valid-config.mjs";
import { createTestOAuthTokenSettings } from "../../testing/slots/oauthTokenSettings.mjs";
import { unfrozenPath } from "../../testing/slots/shared.mjs";
import { createApp } from "../create-app.mjs";
import { BootError, type BootstrapMap } from "../types.mjs";

declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly "test.configWriter": object;
		readonly "test.configReader": object;
	}
}

// The fixture configuration resolves a 3600 s access-token maximum.
const CONFIGURED_ACCESS_MAX = 3600;

interface ConfigShape {
	oauth: { accessToken: Record<string, unknown> };
	core: { deployment: Record<string, unknown> };
}

const hostConfig = (): ConfigShape =>
	({
		...makeValidCoreConfig(),
		core: { ...makeValidCoreConfig().core, deployment: { mode: "single" } },
	}) as unknown as ConfigShape;

const bootstrap = (config: ConfigShape): BootstrapMap =>
	({ config, pathResolver: (s: string) => s }) as unknown as BootstrapMap;

/** A module that tries to change the configuration every later reader sees. */
function configWriter(outcomes: Record<string, string>): Module {
	const attempt = (label: string, write: () => void) => {
		try {
			write();
			outcomes[label] = "allowed";
		} catch (err) {
			outcomes[label] = (err as Error).constructor.name;
		}
	};
	return defineModule({
		name: "test:config-writer",
		requires: ["config"] as never,
		provides: {
			"test.configWriter": (deps: { config: ConfigShape }) => {
				attempt("oauth.accessToken.maxExpiresIn", () => {
					deps.config.oauth.accessToken.maxExpiresIn = 7200;
				});
				attempt("core.deployment.mode", () => {
					deps.config.core.deployment.mode = "multi";
				});
				attempt("core.deployment", () => {
					(deps.config.core as Record<string, unknown>).deployment = { mode: "multi" };
				});
				return {};
			},
		} as never,
	});
}

describe("the config slot is frozen before any module receives it", () => {
	it("refuses a module's writes with a TypeError, so the lifetime gate still holds a later provider to the configuration", async () => {
		const outcomes: Record<string, string> = {};
		const seen: { maxExpiresIn?: unknown; mode?: unknown } = {};
		const provider: Module = defineModule({
			name: "test:token-settings-provider",
			requires: ["config", "test.configWriter"] as never,
			provides: {
				oauthTokenSettings: (deps: { config: ConfigShape }) => {
					seen.maxExpiresIn = deps.config.oauth.accessToken.maxExpiresIn;
					seen.mode = deps.config.core.deployment.mode;
					return createTestOAuthTokenSettings({
						accessTokenLifetime: { defaultExpiresIn: 600, maxExpiresIn: 7200 },
					});
				},
			} as never,
			lifecycle: { oauthTokenSettings: { eager: true } } as never,
		});

		const booting = createApp({
			modules: [configWriter(outcomes), provider],
			bootstrapComponents: bootstrap(hostConfig()),
		});
		await expect(booting).rejects.toBeInstanceOf(BootError);
		await expect(booting).rejects.toMatchObject({
			reason: "token-settings-lifetime-exceeds-configuration",
			stage: "materializeComponents",
			details: {
				member: "accessTokenLifetime.maxExpiresIn",
				slotSeconds: 7200,
				configurationSeconds: CONFIGURED_ACCESS_MAX,
			},
		});
		expect(outcomes).toEqual({
			"oauth.accessToken.maxExpiresIn": "TypeError",
			"core.deployment.mode": "TypeError",
			"core.deployment": "TypeError",
		});
		expect(seen).toEqual({ maxExpiresIn: undefined, mode: "single" });
	});

	it("holds the config slot frozen all the way down once boot has finished, and a later module reads the values as parsed", async () => {
		const outcomes: Record<string, string> = {};
		let read: ConfigShape | undefined;
		const reader: Module = defineModule({
			name: "test:config-reader",
			requires: ["config", "test.configWriter"] as never,
			provides: {
				"test.configReader": (deps: { config: ConfigShape }) => {
					read = deps.config;
					return {};
				},
			} as never,
			lifecycle: { "test.configReader": { eager: true } } as never,
		});
		const host = hostConfig();

		const handle = await createApp({
			modules: [configWriter(outcomes), reader],
			bootstrapComponents: bootstrap(host),
		});
		try {
			const config = handle.components.config as unknown as ConfigShape;
			expect(unfrozenPath(config, "config")).toBeUndefined();
			expect(read).toBe(config);
			expect(Object.values(outcomes)).toEqual(["TypeError", "TypeError", "TypeError"]);
			expect(config.oauth.accessToken.maxExpiresIn).toBeUndefined();
			expect(config.core.deployment).toEqual({ mode: "single" });
			expect(handle.components.deploymentMode).toBe("single");
			// The host's own object is not the slot's, and is left unfrozen.
			expect(config).not.toBe(host);
			expect(Object.isFrozen(host)).toBe(false);
			expect(Object.isFrozen(host.oauth.accessToken)).toBe(false);
		} finally {
			await handle.dispose();
		}
	});
});
