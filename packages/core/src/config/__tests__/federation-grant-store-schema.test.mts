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

import { describe, expect, it } from "vitest";
import { AppConfigSchema } from "#/config/application.schema.mjs";
import { makeValidAppConfig } from "#/testing/fixtures/valid-config.mjs";

/**
 * #593 slice 7 — the two adapter switches the standalone template composes
 * federation grants from. Declared here for the reason every switch above
 * them is (`federationTokenStore.type` is the standing example): a key
 * `AppConfigSchema` does not know is stripped before `buildModules` reads it,
 * and the operator's choice silently becomes the default. Two switches, not
 * one, because the grant store and the intent store are installed
 * independently — grants in Redis with acquisition in memory is a supported
 * single-replica shape (a restart loses flows in progress, nothing else).
 */
const base = makeValidAppConfig();

describe("federationGrantStore.adapter (#593 slice 7)", () => {
	it.each(["memory", "redis"] as const)("accepts %s", (adapter) => {
		expect(
			AppConfigSchema.parse({ ...base, federationGrantStore: { adapter } }).federationGrantStore,
		).toEqual({ adapter });
	});

	it("refuses an adapter it does not know, by name", () => {
		expect(() =>
			AppConfigSchema.parse({ ...base, federationGrantStore: { adapter: "postgres" } }),
		).toThrow(/federationGrantStore/);
	});
});

describe("federationGrantIntentStore.adapter (#593 slice 7)", () => {
	it.each(["memory", "redis"] as const)("accepts %s", (adapter) => {
		expect(
			AppConfigSchema.parse({ ...base, federationGrantIntentStore: { adapter } })
				.federationGrantIntentStore,
		).toEqual({ adapter });
	});

	it("refuses an adapter it does not know, by name", () => {
		expect(() =>
			AppConfigSchema.parse({ ...base, federationGrantIntentStore: { adapter: "postgres" } }),
		).toThrow(/federationGrantIntentStore/);
	});

	it("is absent when omitted — the default lives in reference.conf", () => {
		expect(AppConfigSchema.parse(base).federationGrantStore).toBeUndefined();
		expect(AppConfigSchema.parse(base).federationGrantIntentStore).toBeUndefined();
	});
});
