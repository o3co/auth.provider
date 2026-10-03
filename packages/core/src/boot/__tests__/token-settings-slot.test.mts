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
 * The `oauthTokenSettings` slot holds one snapshot: boot holds whatever
 * fills it — a host's bootstrap or override value, or a module's provided
 * value — to its contract and to the lifetimes core resolves from the
 * configuration as the value enters the component map, and the map keeps
 * the frozen snapshot that check answered. Every consumer reads that one
 * snapshot, so a value that answers differently from one read to the next
 * (a getter, a Proxy, an object changed later) cannot hand a consumer a
 * lifetime the check never saw.
 */

import { describe, expect, it } from "vitest";
import type { GrantHandler } from "../../grants/types.mjs";
import { createApp } from "../../index.mjs";
import { defineModule } from "../../modules/manifest/index.mjs";
import { makeValidCoreConfig } from "../../testing/fixtures/valid-config.mjs";
import { createTestOAuthTokenSettings } from "../../testing/slots/oauthTokenSettings.mjs";
import { checkOAuthTokenSettings } from "../../token-settings/check.mjs";
import type { OAuthTokenSettings } from "../../token-settings/types.mjs";
import { BootError } from "../types.mjs";

declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		tokenSettingsSlotProbe?: { readonly probed: true };
	}
}

// The fixture configuration resolves a 86 400 s refresh-token lifetime.
const CONFIGURED_REFRESH = 86_400;
const LONGER_REFRESH = CONFIGURED_REFRESH * 2;

const host = () => ({ config: makeValidCoreConfig(), pathResolver: (p: string) => p });

/** What each consumer was handed, and what it read of it with the one-argument check. */
interface Seen {
	readonly handed: unknown;
	readonly read: OAuthTokenSettings;
}

/**
 * Two consumers of the slot: a provider (stage 3) and a grant (stage 4).
 * `arm` runs before either reads anything, so a value can change its answers
 * from the first consumer read on.
 */
const consumers = (seen: Seen[], arm: () => void = () => {}) => {
	const record = (handed: unknown) => {
		arm();
		seen.push({ handed, read: checkOAuthTokenSettings(handed) });
	};
	return [
		defineModule({
			name: "test:token-settings-provider-consumer",
			optional: ["oauthTokenSettings"],
			provides: {
				tokenSettingsSlotProbe: (deps) => {
					record(deps.oauthTokenSettings);
					return { probed: true } as const;
				},
			},
			lifecycle: { tokenSettingsSlotProbe: { eager: true } },
		}),
		defineModule({
			name: "test:token-settings-grant-consumer",
			optional: ["oauthTokenSettings"],
			contributes: {
				grants: {
					"urn:test:token-settings-slot": (deps): GrantHandler => {
						record(deps.oauthTokenSettings);
						return { handle: async () => ({ result: { status: 200, tokens: {} as never } }) };
					},
				},
			},
		}),
	];
};

/** The double's settings, with a refresh-token lifetime that answers in bound until `armed()`. */
const changingAfter = (armed: () => boolean): Record<string, unknown> => {
	const base = createTestOAuthTokenSettings();
	return {
		...base,
		accessTokenLifetime: { ...base.accessTokenLifetime },
		get refreshTokenExpiresIn() {
			return armed() ? LONGER_REFRESH : CONFIGURED_REFRESH;
		},
	};
};

const expectOneSnapshot = (seen: readonly Seen[], held: unknown, raw: unknown): void => {
	expect(seen).toHaveLength(2);
	for (const { handed, read } of seen) {
		// The map's snapshot itself: frozen, the same object for every consumer.
		expect(handed).toBe(held);
		expect(handed).not.toBe(raw);
		expect(Object.isFrozen(handed)).toBe(true);
		expect(read.refreshTokenExpiresIn).toBe(CONFIGURED_REFRESH);
	}
};

describe("the oauthTokenSettings slot holds one checked snapshot", () => {
	it("hands every consumer the snapshot of a module's value, never what a getter answers later", async () => {
		let armed = false;
		const provided = changingAfter(() => armed);
		const seen: Seen[] = [];
		const handle = await createApp({
			modules: [
				defineModule({
					name: "test:token-settings-source",
					provides: { oauthTokenSettings: () => provided as never },
					lifecycle: { oauthTokenSettings: { eager: true } },
				}),
				...consumers(seen, () => {
					armed = true;
				}),
			],
			bootstrapComponents: host() as never,
		});
		expectOneSnapshot(seen, handle.components.oauthTokenSettings, provided);
		await handle.dispose();
	});

	it("hands every consumer the snapshot of a host's Proxy, never what it answers later", async () => {
		let armed = false;
		const target = changingAfter(() => armed);
		const proxy = new Proxy(target, {});
		const seen: Seen[] = [];
		const handle = await createApp({
			modules: consumers(seen, () => {
				armed = true;
			}),
			bootstrapComponents: { ...host(), oauthTokenSettings: proxy } as never,
		});
		expectOneSnapshot(seen, handle.components.oauthTokenSettings, proxy);
		await handle.dispose();
	});

	it("holds an overriding host value to the same snapshot", async () => {
		const value = { ...createTestOAuthTokenSettings() };
		const seen: Seen[] = [];
		const handle = await createApp({
			modules: consumers(seen),
			bootstrapComponents: host() as never,
			overrideComponents: { oauthTokenSettings: value },
		});
		expectOneSnapshot(seen, handle.components.oauthTokenSettings, value);
		await handle.dispose();
	});

	it("refuses a module's value beyond the configured lifetimes as it is materialised, naming the module, and cleans up", async () => {
		const cleaned: unknown[] = [];
		const value = createTestOAuthTokenSettings({ refreshTokenExpiresIn: LONGER_REFRESH });
		const seen: Seen[] = [];
		const caught = await createApp({
			modules: [
				defineModule({
					name: "test:token-settings-source",
					provides: { oauthTokenSettings: () => value },
					lifecycle: {
						oauthTokenSettings: { eager: true, cleanup: (v) => void cleaned.push(v) },
					},
				}),
				...consumers(seen),
			],
			bootstrapComponents: host() as never,
		}).then(
			() => undefined,
			(err: unknown) => err,
		);
		expect(caught).toBeInstanceOf(BootError);
		const err = caught as BootError;
		expect(err.reason).toBe("token-settings-lifetime-exceeds-configuration");
		expect(err.stage).toBe("materializeComponents");
		expect(err.details).toEqual({
			reason: "token-settings-lifetime-exceeds-configuration",
			componentKey: "oauthTokenSettings",
			source: "provides",
			module: "test:token-settings-source",
			member: "refreshTokenExpiresIn",
			slotSeconds: LONGER_REFRESH,
			configurationSeconds: CONFIGURED_REFRESH,
		});
		expect(err.message).toMatch(/test:token-settings-source/);
		expect(seen).toEqual([]);
		expect(cleaned).toEqual([value]);
	});

	it("refuses a module's value that breaks the contract as it is materialised, naming the member", async () => {
		const { issuer: _issuer, ...withoutIssuer } = createTestOAuthTokenSettings();
		const seen: Seen[] = [];
		const caught = await createApp({
			modules: [
				defineModule({
					name: "test:token-settings-source",
					provides: { oauthTokenSettings: () => withoutIssuer as never },
					lifecycle: { oauthTokenSettings: { eager: true } },
				}),
				...consumers(seen),
			],
			bootstrapComponents: host() as never,
		}).then(
			() => undefined,
			(err: unknown) => err,
		);
		expect(caught).toBeInstanceOf(BootError);
		const err = caught as BootError;
		expect(err.reason).toBe("provides-factory-failed");
		expect(err.stage).toBe("materializeComponents");
		expect(err.cause).toBeInstanceOf(RangeError);
		expect(err.message).toMatch(/oauthTokenSettings\.issuer/);
		expect(seen).toEqual([]);
	});

	it("refuses a host's value that breaks the contract before any provider runs, naming the member", async () => {
		const { issuer: _issuer, ...withoutIssuer } = createTestOAuthTokenSettings();
		const seen: Seen[] = [];
		await expect(
			createApp({
				modules: consumers(seen),
				bootstrapComponents: { ...host(), oauthTokenSettings: withoutIssuer } as never,
			}),
		).rejects.toThrow(/oauthTokenSettings\.issuer/);
		expect(seen).toEqual([]);
	});
});
