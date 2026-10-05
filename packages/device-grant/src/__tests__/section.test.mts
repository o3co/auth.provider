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
 * The schema of `device-grant {}`, the module's own section, and the switch
 * read from it: the section holds no default of its own — every value a
 * deployment does not write comes from the package's `config/reference.conf`
 * — reads an absent section or an absent `enabled` as off, and refuses an
 * unknown key at every level, naming its path. The module is one constant,
 * whatever configuration a composition holds.
 */

import { sectionStrictnessProblems } from "@o3co/auth-provider-core/testing";
import { describe, expect, it } from "vitest";
import { deviceAuthorizationGrantModule, deviceGrantConfigSchema } from "#/module.mjs";
import { referenceTree, shippedDeviceGrantSection } from "./shippedSection.mjs";

/** The paths `section`'s parse refuses, sorted. */
const refusedPaths = (section: unknown): string[] =>
	(deviceGrantConfigSchema.safeParse(section).error?.issues ?? [])
		.map((issue) => issue.path.map(String).join("."))
		.sort();

const isEnabled = (section: unknown): unknown =>
	deviceAuthorizationGrantModule.section?.isEnabled?.(deviceGrantConfigSchema.parse(section));

describe("the device-grant section", () => {
	it("resolves its defaults from the package's reference.conf alone", () => {
		expect(deviceGrantConfigSchema.parse(shippedDeviceGrantSection())).toStrictEqual({
			enabled: false,
			verificationUriComplete: false,
			codeLifetimeSeconds: 600,
			pollingIntervalSeconds: 5,
			rateLimit: { limit: 5, windowSeconds: 300 },
		});
	});

	it("holds no default of its own: a key the reference ships and the section lacks refuses, naming it", () => {
		expect(refusedPaths({ enabled: true })).toEqual([
			"codeLifetimeSeconds",
			"pollingIntervalSeconds",
			"rateLimit",
			"verificationUriComplete",
		]);
		expect(refusedPaths(shippedDeviceGrantSection({ rateLimit: {} }))).toEqual([
			"rateLimit.limit",
			"rateLimit.windowSeconds",
		]);
	});

	it("reads an absent section, and a section without enabled, as off", () => {
		expect(deviceGrantConfigSchema.parse(undefined)).toBeUndefined();
		expect(isEnabled(undefined)).toBe(false);
		const { enabled: _enabled, ...withoutSwitch } = shippedDeviceGrantSection();
		expect(isEnabled(withoutSwitch)).toBe(false);
		expect(isEnabled(shippedDeviceGrantSection())).toBe(false);
		expect(isEnabled(shippedDeviceGrantSection({ enabled: "true" }))).toBe(true);
		expect(isEnabled(shippedDeviceGrantSection({ enabled: true }))).toBe(true);
	});

	it("refuses an unknown key at every level of the section, naming its path", () => {
		expect(
			sectionStrictnessProblems([deviceAuthorizationGrantModule], {
				tree: referenceTree(),
				samples: {
					"device-grant": [
						shippedDeviceGrantSection({
							enabled: true,
							verificationUri: "https://example.test/device",
							store: "unsupported",
						}),
					],
				},
			}),
		).toEqual([]);
		expect(refusedPaths(shippedDeviceGrantSection({ typo: 1 }))).toEqual([""]);
		expect(
			refusedPaths(
				shippedDeviceGrantSection({ rateLimit: { limit: 5, windowSeconds: 300, typo: 1 } }),
			),
		).toEqual(["rateLimit"]);
	});
});

describe("the device-grant module", () => {
	it("is one module, switched by its own section", () => {
		expect(deviceAuthorizationGrantModule.name).toBe("device-grant");
		expect(typeof deviceAuthorizationGrantModule.section?.isEnabled).toBe("function");
	});

	it("reads no whole configuration: it requires oauthTokenSettings, and neither requires nor reads config", () => {
		expect(deviceAuthorizationGrantModule.requires).toContain("oauthTokenSettings");
		expect(deviceAuthorizationGrantModule.requires).not.toContain("config");
		expect(deviceAuthorizationGrantModule.optional).not.toContain("config");
		expect(deviceAuthorizationGrantModule.optional).not.toContain("oauthTokenSettings");
	});
});
