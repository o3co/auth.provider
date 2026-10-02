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
 * The template's MFA switch in a project scaffolded without MFA: nothing of
 * MFA is installed or handed to boot, the `acr` table and discovery are as
 * written, and asking for MFA — `MFA_MODE`, a file's `mfaMode`, a written
 * `mfa.mode` — is refused before boot. Booted through the all-modules
 * fixture.
 */

import { BootError } from "@o3co/auth-provider-core";
import request from "supertest";
import { afterEach, describe, expect, it } from "vitest";
import { readOwnLayers, readSwitches, resolveLayers } from "#/configPath.mjs";
import { templateReference } from "#/modules.mjs";
import {
	type Composition,
	compose,
	ownFiles,
	SINGLE_ENV,
} from "./all-modules-composition.fixture.mjs";

let current: Composition | undefined;

afterEach(async () => {
	await current?.handle.dispose();
	current = undefined;
});

/** The boot's refusal, or `undefined` when it booted (kept for disposal). */
const refusal = (composing: Promise<Composition>): Promise<unknown> =>
	composing.then(
		(composition) => {
			current = composition;
			return undefined;
		},
		(caught: unknown) => caught,
	);

describe("a project without MFA", () => {
	it("ships no MFA switch and no mfa section in its configuration", () => {
		const resolved = resolveLayers(readOwnLayers(ownFiles(), { env: SINGLE_ENV }), [
			templateReference(),
		]);
		expect(resolved).not.toHaveProperty("mfaMode");
		expect(resolved).not.toHaveProperty("mfa");
	});

	it("reads the switch as off, with MFA_MODE unset or off", () => {
		const switches = (env: Readonly<Record<string, string>>) =>
			readSwitches(readOwnLayers(ownFiles(), { env })).mfaMode;
		expect(switches(SINGLE_ENV)).toBe("off");
		expect(switches({ ...SINGLE_ENV, MFA_MODE: "off" })).toBe("off");
	});

	it("boots with nothing of MFA, and no acr entry, discovery value or acr line from it", async () => {
		current = await compose();
		expect(current.modules.map((m) => m.name).filter((name) => /mfa/i.test(name))).toEqual([]);
		expect(current.resolved).not.toHaveProperty("mfa");
		expect([...(current.handle.components.sessionRequirementResolver?.entries() ?? [])]).toEqual(
			[],
		);
		const acrValues = (
			current.resolved as unknown as { oauth: { authorize?: { acrValues?: object } } }
		).oauth.authorize?.acrValues;
		expect(acrValues ?? {}).not.toHaveProperty(["urn:o3co:acr:mfa"]);
		const doc = await request(current.app).get("/.well-known/openid-configuration");
		expect(doc.body).not.toHaveProperty("acr_values_supported");
		expect(
			current.logger.lines.filter((line) => line.args[1] === "acr_value_unsatisfiable"),
		).toEqual([]);
	});

	it.each([
		["MFA_MODE=required", { MFA_MODE: "required" }, undefined],
		["MFA_MODE=optional", { MFA_MODE: "optional" }, undefined],
		["MFA_MODE set to none of the modes", { MFA_MODE: "sentinel-mode" }, undefined],
		["a file's mfaMode", {}, 'mfaMode = "required"\n'],
	])(
		"refuses %s before boot, naming mfaMode and MFA_MODE and quoting nothing",
		async (_case, env, operatorHocon) => {
			const err = await refusal(
				compose({
					env: { ...SINGLE_ENV, ...env },
					...(operatorHocon === undefined ? {} : { operatorHocon }),
				}),
			);
			expect(err).toBeInstanceOf(RangeError);
			expect(err).not.toBeInstanceOf(BootError);
			const message = (err as RangeError).message;
			expect(message).toContain("mfaMode");
			expect(message).toContain("MFA_MODE");
			expect(message).toContain("without MFA");
			expect(message).not.toMatch(/required|optional|sentinel-mode/);
		},
	);

	it("refuses an mfa.mode the configuration writes other than off, and boots with one that says off", async () => {
		const err = await refusal(compose({ operatorHocon: 'mfa.mode = "required"\n' }));
		expect(err).toBeInstanceOf(RangeError);
		expect((err as RangeError).message).toContain("mfa.mode");
		expect((err as RangeError).message).not.toContain("required");
		current = await compose({ operatorHocon: 'mfa.mode = "off"\n' });
		expect(current.resolved).not.toHaveProperty("mfa");
	});
});
