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
 * Each factor module's `enabled` is the module's switch (`section.isEnabled`):
 * off, the module registers nothing, so its factor kind is neither in
 * `mfaFactorResolver` nor claimed, and another module may contribute it.
 */

import { createApp, defineModule, type Module } from "@o3co/auth-provider-core";
import { makeValidAppConfig } from "@o3co/auth-provider-core/testing";
import { describe, expect, it } from "vitest";
import { EMAIL_FACTOR_KIND } from "#/email/factor.mjs";
import { mfaEmailFactorModule } from "#/email/module.mjs";
import { RECOVERY_CODE_FACTOR_KIND } from "#/recovery/factor.mjs";
import { mfaRecoveryCodeFactorModule } from "#/recovery/module.mjs";
import {
	mfaEmailFactorConfigForTests,
	mfaRecoveryCodeFactorConfigForTests,
	mfaTotpFactorConfigForTests,
} from "#/testing/index.mjs";
import { TOTP_FACTOR_KIND } from "#/totp/factor.mjs";
import { mfaTotpFactorModule } from "#/totp/module.mjs";
import { UNSET_RENAMED_VARIABLES } from "./moduleHarness.mjs";

/** Each factor module, its kind, and its section as the package's builder makes it. */
const FACTORS = [
	{
		name: mfaTotpFactorModule.name,
		module: mfaTotpFactorModule as Module,
		kind: TOTP_FACTOR_KIND,
		section: (enabled: boolean) => mfaTotpFactorConfigForTests({ enabled }),
	},
	{
		name: mfaRecoveryCodeFactorModule.name,
		module: mfaRecoveryCodeFactorModule as Module,
		kind: RECOVERY_CODE_FACTOR_KIND,
		section: (enabled: boolean) => mfaRecoveryCodeFactorConfigForTests({ enabled }),
	},
	{
		name: mfaEmailFactorModule.name,
		module: mfaEmailFactorModule as Module,
		kind: EMAIL_FACTOR_KIND,
		section: (enabled: boolean) => mfaEmailFactorConfigForTests({ enabled }),
	},
];

/** The section the module reads, out of what its builder makes, parsed by its schema. */
const parsed = (module: Module, written: Readonly<Record<string, unknown>>): unknown =>
	module.section?.schema.parse(written[module.name]);

describe.each(FACTORS)("$name", ({ module, kind, section }) => {
	it(`${module.name}.enabled is the module's switch`, () => {
		const isEnabled = module.section?.isEnabled;
		expect(isEnabled?.call(module.section, parsed(module, section(false)))).toBe(false);
		expect(isEnabled?.call(module.section, parsed(module, section(true)))).toBe(true);
	});

	it(`switched off, ${module.name} claims nothing: another module may contribute ${kind}`, async () => {
		const other = defineModule({
			name: "test:same-kind",
			contributes: { mfaFactors: { [kind]: () => null } },
		});
		const base = makeValidAppConfig();
		const handle = await createApp({
			modules: [module, other],
			bootstrapComponents: {
				config: {
					...base,
					oauth: { ...base.oauth, jwt: { ...base.oauth.jwt, issuer: "https://login.example" } },
					...section(false),
					"renamed-variables": UNSET_RENAMED_VARIABLES,
				},
				pathResolver: (p: string) => p,
			} as never,
		});
		try {
			expect([...(handle.components.mfaFactorResolver?.entries() ?? [])]).toEqual([]);
		} finally {
			await handle.dispose();
		}
	});
});
