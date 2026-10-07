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
 * The `config` slot — the configuration stage 1 parsed — is one object core's
 * own modules read, and core reads it again after providers have run (the
 * stage-3 lifetime gate on `oauthTokenSettings`, the slots it holds to
 * declared absence, the app's settings). No other module reaches it: one that
 * lists it is refused before any factory runs. Boot holds it as a frozen copy
 * of plain data: a write throws (`TypeError`, in strict-mode code), so no
 * reader changes what core reads, and the host's own configuration object is
 * left as the host made it.
 */

import { describe, expect, it, vi } from "vitest";
import { defineModule, type Module } from "../../modules/manifest/index.mjs";
import { makeValidCoreConfig } from "../../testing/fixtures/valid-config.mjs";
import { createTestOAuthTokenSettings } from "../../testing/slots/oauthTokenSettings.mjs";
import { unfrozenPath } from "../../testing/slots/shared.mjs";
import { createApp } from "../create-app.mjs";
import { BootError, type BootstrapMap } from "../types.mjs";

declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly "test.configWriter": object;
	}
}

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

/** Tries three writes to `config`, recording what each did. */
function attemptWrites(config: ConfigShape, outcomes: Record<string, string>): void {
	const attempt = (label: string, write: () => void) => {
		try {
			write();
			outcomes[label] = "allowed";
		} catch (err) {
			outcomes[label] = (err as Error).constructor.name;
		}
	};
	attempt("oauth.accessToken.maxExpiresIn", () => {
		config.oauth.accessToken.maxExpiresIn = 7200;
	});
	attempt("core.deployment.mode", () => {
		config.core.deployment.mode = "multi";
	});
	attempt("core.deployment", () => {
		(config.core as Record<string, unknown>).deployment = { mode: "multi" };
	});
}

/** A module outside core that tries to change the configuration every later reader sees. */
function configWriter(outcomes: Record<string, string>): Module {
	return defineModule({
		name: "test:config-writer",
		requires: ["config"] as never,
		provides: {
			"test.configWriter": (deps: { config: ConfigShape }) => {
				attemptWrites(deps.config, outcomes);
				return {};
			},
		} as never,
	});
}

describe("the config slot is frozen, and no module outside core reaches it", () => {
	it("refuses a module outside core that would write it before any factory runs, so the lifetime gate reads the configuration", async () => {
		const outcomes: Record<string, string> = {};
		const provided = vi.fn();
		const provider: Module = defineModule({
			name: "test:token-settings-provider",
			requires: ["test.configWriter"] as never,
			provides: {
				oauthTokenSettings: () => {
					provided();
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
			reason: "reserved-component-key",
			stage: "validateManifests",
			details: { componentKey: "config", module: "test:config-writer" },
		});
		expect(outcomes).toEqual({});
		expect(provided).not.toHaveBeenCalled();
	});

	it("holds the config slot frozen all the way down once boot has finished, the values as parsed", async () => {
		const host = hostConfig();

		const handle = await createApp({
			modules: [],
			bootstrapComponents: bootstrap(host),
		});
		try {
			const config = handle.components.config as unknown as ConfigShape;
			expect(unfrozenPath(config, "config")).toBeUndefined();
			const outcomes: Record<string, string> = {};
			attemptWrites(config, outcomes);
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
