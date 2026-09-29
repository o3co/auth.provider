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

import { describe, expect, it } from "vitest";
import { createApp } from "../../index.mjs";
import { defineModule } from "../../modules/manifest/index.mjs";
import { makeValidCoreConfig } from "../../testing/fixtures/valid-config.mjs";
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

	it("refuses an authoritative that is not a list of keys", async () => {
		const err = await refusal(
			createApp({
				modules: [
					defineModule({
						name: "test:not-a-list",
						provides: { oauthTokenSettings: () => OWNED },
						authoritative: "oauthTokenSettings" as never,
					}),
				],
				bootstrapComponents: bootstrap(),
			}),
		);
		expect(err.reason).toBe("authoritative-without-provides");
		expect(err.message).toMatch(/list/);
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
