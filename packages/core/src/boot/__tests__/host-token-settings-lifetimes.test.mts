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
 * An `oauthTokenSettings` a host fills (through `bootstrapComponents` or
 * `overrideComponents`) may not name a token lifetime longer than the one
 * core resolves from the configuration. The default refresh-token family
 * modules and the subject revocation boundary size their retention from the
 * configuration and cannot read the slot, so a grant minting on a longer slot
 * lifetime would outlive the record that revokes its token
 * (docs/adapter-surface.md, `oauthTokenSettings`). Boot refuses the pair,
 * naming the member and both values: a host map at stage 1, before any
 * provider runs, and a value a module provides where a reader first reads it.
 */

import { describe, expect, it } from "vitest";
import { createApp } from "../../index.mjs";
import { defineModule } from "../../modules/manifest/index.mjs";
import { makeValidCoreConfig } from "../../testing/fixtures/valid-config.mjs";
import { createTestOAuthTokenSettings } from "../../testing/slots/oauthTokenSettings.mjs";
import { BootError } from "../types.mjs";

// The fixture configuration resolves a 3600 s access-token default and
// maximum and a 86 400 s refresh-token lifetime.
const CONFIGURED_ACCESS_MAX = 3600;
const CONFIGURED_REFRESH = 86_400;

const config = () => makeValidCoreConfig();

const refusal = async (booting: Promise<unknown>): Promise<BootError> => {
	const caught = await booting.then(
		async (handle) => {
			await (handle as { dispose(): Promise<void> }).dispose();
			return undefined;
		},
		(err: unknown) => err,
	);
	expect(caught).toBeInstanceOf(BootError);
	return caught as BootError;
};

describe("a host-filled oauthTokenSettings is held to the configuration's lifetimes", () => {
	it("refuses a bootstrapped slot whose access-token maximum outlasts the configuration's, naming the member and both values", async () => {
		const err = await refusal(
			createApp({
				modules: [],
				bootstrapComponents: {
					config: config(),
					pathResolver: (p: string) => p,
					oauthTokenSettings: createTestOAuthTokenSettings({
						accessTokenLifetime: { defaultExpiresIn: 600, maxExpiresIn: 7200 },
					}),
				} as never,
			}),
		);
		expect(err.reason).toBe("token-settings-lifetime-exceeds-configuration");
		expect(err.stage).toBe("validateManifests");
		expect(err.details).toEqual({
			reason: "token-settings-lifetime-exceeds-configuration",
			componentKey: "oauthTokenSettings",
			source: "bootstrapComponents",
			member: "accessTokenLifetime.maxExpiresIn",
			slotSeconds: 7200,
			configurationSeconds: CONFIGURED_ACCESS_MAX,
		});
		expect(err.message).toMatch(/accessTokenLifetime\.maxExpiresIn/);
		expect(err.message).toMatch(/7200/);
		expect(err.message).toMatch(/3600/);
	});

	it("refuses an overriding slot whose refresh-token lifetime outlasts the configuration's", async () => {
		const err = await refusal(
			createApp({
				modules: [],
				bootstrapComponents: { config: config(), pathResolver: (p: string) => p } as never,
				overrideComponents: {
					oauthTokenSettings: createTestOAuthTokenSettings({
						refreshTokenExpiresIn: CONFIGURED_REFRESH + 1,
					}),
				},
			}),
		);
		expect(err.reason).toBe("token-settings-lifetime-exceeds-configuration");
		expect(err.details).toEqual({
			reason: "token-settings-lifetime-exceeds-configuration",
			componentKey: "oauthTokenSettings",
			source: "overrideComponents",
			member: "refreshTokenExpiresIn",
			slotSeconds: CONFIGURED_REFRESH + 1,
			configurationSeconds: CONFIGURED_REFRESH,
		});
	});

	it("boots a host slot whose lifetimes are the configuration's or shorter", async () => {
		for (const settings of [
			createTestOAuthTokenSettings(),
			createTestOAuthTokenSettings({
				accessTokenLifetime: { defaultExpiresIn: 60, maxExpiresIn: 600 },
				refreshTokenExpiresIn: 3600,
			}),
		]) {
			const handle = await createApp({
				modules: [],
				bootstrapComponents: {
					config: config(),
					pathResolver: (p: string) => p,
					oauthTokenSettings: settings,
				} as never,
			});
			await handle.dispose();
		}
	});

	it("refuses a slot a module provides that outlasts the configuration's, where a reader reads it", async () => {
		// Not oauthModule, whose provider resolves its lifetimes from the same
		// configuration: another module, advertising a longer refresh token.
		const booting = createApp({
			modules: [
				defineModule({
					name: "test:token-settings-provider",
					provides: {
						oauthTokenSettings: () =>
							createTestOAuthTokenSettings({ refreshTokenExpiresIn: CONFIGURED_REFRESH * 2 }),
					},
					lifecycle: { oauthTokenSettings: { eager: true } },
				}),
			],
			bootstrapComponents: { config: config(), pathResolver: (p: string) => p } as never,
		});
		await expect(booting).rejects.toThrow(RangeError);
		await expect(booting).rejects.toThrow(
			/oauthTokenSettings\.refreshTokenExpiresIn.*172800.*86400/,
		);
	});
});
