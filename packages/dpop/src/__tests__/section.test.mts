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
 * The schema of `dpop {}`, the module's own section: it holds no default of
 * its own — every value a deployment does not write comes from the package's
 * `config/reference.conf` — reads an absent section or an absent `enabled`
 * as off, and refuses an unknown key at every level, naming its path.
 */

import { sectionStrictnessProblems } from "@o3co/auth-provider-core/testing";
import { describe, expect, it } from "vitest";
import { dpopConfigSchema, dpopModule } from "#/module.mjs";
import { referenceTree, shippedDpopSection } from "./shippedSection.mjs";

/** The paths `section`'s parse refuses, sorted. */
const refusedPaths = (section: unknown): string[] =>
	(dpopConfigSchema.safeParse(section).error?.issues ?? [])
		.map((issue) => issue.path.map(String).join("."))
		.sort();

const isEnabled = (section: unknown): unknown =>
	dpopModule.section?.isEnabled?.(dpopConfigSchema.parse(section));

describe("the dpop section", () => {
	it("resolves its defaults from the package's reference.conf alone", () => {
		expect(dpopConfigSchema.parse(shippedDpopSection())).toStrictEqual({
			enabled: false,
			iatWindowSeconds: 60,
			algWhitelist: ["ES256", "ES384", "EdDSA", "RS256"],
			replayStoreTtlSeconds: 300,
			nonce: { required: "never", ttlSeconds: 300 },
		});
	});

	it("holds no default of its own: a key the reference ships and the section lacks refuses, naming it", () => {
		expect(refusedPaths({ enabled: true })).toEqual([
			"algWhitelist",
			"iatWindowSeconds",
			"nonce",
			"replayStoreTtlSeconds",
		]);
		expect(refusedPaths(shippedDpopSection({ nonce: {} }))).toEqual([
			"nonce.required",
			"nonce.ttlSeconds",
		]);
	});

	it("reads an absent section, and a section without enabled, as off", () => {
		expect(dpopConfigSchema.parse(undefined)).toBeUndefined();
		expect(isEnabled(undefined)).toBe(false);
		const { enabled: _enabled, ...withoutSwitch } = shippedDpopSection();
		expect(isEnabled(withoutSwitch)).toBe(false);
		expect(isEnabled(shippedDpopSection())).toBe(false);
		expect(isEnabled(shippedDpopSection({ enabled: "true" }))).toBe(true);
	});

	it("refuses an unknown key at every level of the section, naming its path", () => {
		expect(
			sectionStrictnessProblems([dpopModule], {
				tree: referenceTree(),
				samples: {
					dpop: [shippedDpopSection({ nonce: { required: "as", ttlSeconds: 300, secret: "s" } })],
				},
			}),
		).toEqual([]);
		expect(refusedPaths(shippedDpopSection({ typo: 1 }))).toEqual([""]);
		expect(
			refusedPaths(shippedDpopSection({ nonce: { required: "never", ttlSeconds: 300, typo: 1 } })),
		).toEqual(["nonce"]);
	});
});
