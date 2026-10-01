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
 * The recovery-code factor's section, `mfa-recovery-code-factor` (the MFA
 * ADR's D19 `mfa.recoveryCodes`, in the configuration's own shape): named
 * after its module, its keys camelCase, its defaults in the package's
 * `reference.conf` alone, each key read from the variable its path names,
 * and an unknown key refused by its name. The module declares the section
 * and contributes the recovery-code factor from it.
 */

import { fileURLToPath } from "node:url";
import { BootError, createApp, type MfaFactorResolver } from "@o3co/auth-provider-core";
import { makeValidAppConfig, unreadableModuleLeaves } from "@o3co/auth-provider-core/testing";
import { parseFile } from "@o3co/ts.hocon";
import { afterEach, describe, expect, it } from "vitest";
import { mfaRecoveryCodeFactorConfigSchema } from "#/recovery/config.mjs";
import { mfaRecoveryCodeFactorModule } from "#/recovery/module.mjs";

const REFERENCE = fileURLToPath(new URL("../../config/reference.conf", import.meta.url));

/** The package's reference.conf resolved under `env`, as a composition root layers it. */
const resolved = (env: Record<string, string> = {}) =>
	parseFile(REFERENCE, { env }).toObject() as Record<string, Record<string, unknown>>;

const RECOVERY_DEFAULTS = { enabled: true, count: 10 };

/** The issues' paths and codes `schema` answers for `value`, or none. */
const refusedAt = (
	schema: { safeParse(value: unknown): { success: boolean; error?: { issues: unknown[] } } },
	value: unknown,
): string[] =>
	(schema.safeParse(value).error?.issues ?? []).map((issue) => {
		const { path, code } = issue as { path: PropertyKey[]; code: string };
		return `${path.map(String).join(".")}:${code}`;
	});

describe("mfa-recovery-code-factor, the recovery-code factor's section", () => {
	it("defaults to on, with 10 codes", () => {
		const section = resolved()["mfa-recovery-code-factor"];
		expect(mfaRecoveryCodeFactorConfigSchema.parse(section)).toEqual(RECOVERY_DEFAULTS);
	});

	it("reads each key from the variable its path names", () => {
		const section = resolved({
			MFA_RECOVERY_CODE_FACTOR_ENABLED: "false",
			MFA_RECOVERY_CODE_FACTOR_COUNT: "12",
		})["mfa-recovery-code-factor"];
		expect(mfaRecoveryCodeFactorConfigSchema.parse(section)).toEqual({
			enabled: false,
			count: 12,
		});
	});

	it("refuses a key it does not know, and a count outside 1-20", () => {
		for (const count of [1, 20]) {
			expect(refusedAt(mfaRecoveryCodeFactorConfigSchema, { ...RECOVERY_DEFAULTS, count })).toEqual(
				[],
			);
		}
		expect(
			refusedAt(mfaRecoveryCodeFactorConfigSchema, { ...RECOVERY_DEFAULTS, size: 16 }),
		).toEqual([":unrecognized_keys"]);
		for (const count of [0, 21, 1.5, "ten"]) {
			expect(
				refusedAt(mfaRecoveryCodeFactorConfigSchema, { ...RECOVERY_DEFAULTS, count }),
				String(count),
			).not.toEqual([]);
		}
	});
});

describe("mfaRecoveryCodeFactorModule, which declares the section", () => {
	const base = makeValidAppConfig();
	const configWith = (section: Record<string, unknown>) => ({
		...base,
		"mfa-recovery-code-factor": section,
	});

	let disposable: { dispose(): Promise<void> } | undefined;
	afterEach(async () => {
		await disposable?.dispose();
		disposable = undefined;
	});

	it("is named after its section, reads it at its name, and declares the package's reference.conf", () => {
		const module = mfaRecoveryCodeFactorModule;
		expect(module.name).toBe("mfa-recovery-code-factor");
		expect(module.section?.at).toBeUndefined();
		expect(module.section?.reference?.href).toBe(new URL(`file://${REFERENCE}`).href);
		expect(module.requires ?? []).toEqual([]);
		expect(module.replicaSafety).toBeUndefined();
		expect(unreadableModuleLeaves([module])).toEqual([]);
	});

	it("boots with its defaults, and adds the recovery-code factor to the resolver", async () => {
		const handle = await createApp({
			modules: [mfaRecoveryCodeFactorModule],
			bootstrapComponents: {
				config: configWith(RECOVERY_DEFAULTS),
				pathResolver: (p: string) => p,
			} as never,
		});
		disposable = handle;
		const resolver = handle.components.mfaFactorResolver as MfaFactorResolver;
		expect([...resolver.entries()].map(([kind]) => kind)).toEqual(["recovery_code"]);
	});

	it("refuses the boot for a key its section does not know, naming the section and the key", async () => {
		let refused: unknown;
		try {
			disposable = await createApp({
				modules: [mfaRecoveryCodeFactorModule],
				bootstrapComponents: {
					config: configWith({ ...RECOVERY_DEFAULTS, length: 16 }),
					pathResolver: (p: string) => p,
				} as never,
			});
		} catch (error) {
			refused = error;
		}
		expect(refused).toBeInstanceOf(BootError);
		expect((refused as BootError).reason).toBe("config-validation-failed");
		expect((refused as BootError).message).toContain(
			"mfa-recovery-code-factor: has a key it does not know: length",
		);
	});

	it("contributes the recovery-code factor alone, and provides nothing", () => {
		expect(Object.keys(mfaRecoveryCodeFactorModule.contributes ?? {})).toEqual(["mfaFactors"]);
		expect(Object.keys(mfaRecoveryCodeFactorModule.contributes?.mfaFactors ?? {})).toEqual([
			"recovery_code",
		]);
		expect(mfaRecoveryCodeFactorModule.provides).toBeUndefined();
	});
});
