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
 * The sections of the email factor's module, `mfa-email-factor`, and the
 * recovery-code factor's, `mfa-recovery-code-factor` (the MFA ADR's D19, in
 * #728's shape): each named after its module, its keys camelCase, its
 * defaults in the package's `reference.conf` alone, each key read from the
 * variable its path names, and an unknown key refused. The modules are
 * declared before their factors are built: the email factor's answers no
 * factor while off and refuses the boot when switched on; the recovery-code
 * factor's contributes nothing.
 */

import { fileURLToPath } from "node:url";
import { BootError, createApp, type MfaFactorResolver } from "@o3co/auth-provider-core";
import { makeValidAppConfig, unreadableModuleLeaves } from "@o3co/auth-provider-core/testing";
import { parseFile } from "@o3co/ts.hocon";
import { afterEach, describe, expect, it } from "vitest";
import { mfaEmailFactorConfigSchema } from "#/email/config.mjs";
import { mfaEmailFactorModule } from "#/email/module.mjs";
import { mfaRecoveryCodeFactorConfigSchema } from "#/recovery/config.mjs";
import { mfaRecoveryCodeFactorModule } from "#/recovery/module.mjs";

const REFERENCE = fileURLToPath(new URL("../../config/reference.conf", import.meta.url));

/** The package's reference.conf resolved under `env`, as a composition root layers it. */
const resolved = (env: Record<string, string> = {}) =>
	parseFile(REFERENCE, { env }).toObject() as Record<string, Record<string, unknown>>;

const EMAIL_DEFAULTS = {
	enabled: false,
	addsMfa: false,
	codeTtlSeconds: 600,
	maxSends: 3,
	resendAfterSeconds: 30,
	sendLimit: { limit: 5, windowSeconds: 3600 },
	subject: "Your sign-in code",
	body: "Your sign-in code is {code}. It expires in {minutes} minutes.",
};

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

describe("mfa-email-factor, the email factor's section", () => {
	it("defaults to off, adding no mfa, a code living 600 s, 3 sends 30 s apart, 5 per hour per subject, and the sign-in message", () => {
		const section = resolved()["mfa-email-factor"];
		expect(mfaEmailFactorConfigSchema.parse(section)).toEqual(EMAIL_DEFAULTS);
	});

	it("reads each key from the variable its path names", () => {
		const section = resolved({
			MFA_EMAIL_FACTOR_ENABLED: "true",
			MFA_EMAIL_FACTOR_ADDS_MFA: "true",
			MFA_EMAIL_FACTOR_CODE_TTL_SECONDS: "300",
			MFA_EMAIL_FACTOR_MAX_SENDS: "2",
			MFA_EMAIL_FACTOR_RESEND_AFTER_SECONDS: "60",
			MFA_EMAIL_FACTOR_SEND_LIMIT_LIMIT: "4",
			MFA_EMAIL_FACTOR_SEND_LIMIT_WINDOW_SECONDS: "1800",
			MFA_EMAIL_FACTOR_SUBJECT: "Code",
			MFA_EMAIL_FACTOR_BODY: "Code: {code}",
		})["mfa-email-factor"];
		expect(mfaEmailFactorConfigSchema.parse(section)).toEqual({
			enabled: true,
			addsMfa: true,
			codeTtlSeconds: 300,
			maxSends: 2,
			resendAfterSeconds: 60,
			sendLimit: { limit: 4, windowSeconds: 1800 },
			subject: "Code",
			body: "Code: {code}",
		});
	});

	it("refuses a key it does not know, at its path", () => {
		expect(refusedAt(mfaEmailFactorConfigSchema, { ...EMAIL_DEFAULTS, codeTTL: 600 })).toEqual([
			":unrecognized_keys",
		]);
		expect(
			refusedAt(mfaEmailFactorConfigSchema, {
				...EMAIL_DEFAULTS,
				sendLimit: { ...EMAIL_DEFAULTS.sendLimit, burst: 1 },
			}),
		).toEqual(["sendLimit:unrecognized_keys"]);
	});

	it("holds a code's life to 60-1800 s, its sends to 1-10, the pause between them to 0-600 s, and the per-subject budget to a whole limit and a window of at most a year", () => {
		for (const [key, value] of [
			["codeTtlSeconds", 60],
			["codeTtlSeconds", 1800],
			["maxSends", 1],
			["maxSends", 10],
			["resendAfterSeconds", 0],
			["resendAfterSeconds", 600],
			["sendLimit", { limit: 1, windowSeconds: 31_536_000 }],
		] as const) {
			expect(
				refusedAt(mfaEmailFactorConfigSchema, { ...EMAIL_DEFAULTS, [key]: value }),
				`${key} ${JSON.stringify(value)}`,
			).toEqual([]);
		}
		for (const [key, value] of [
			["codeTtlSeconds", 59],
			["codeTtlSeconds", 1801],
			["maxSends", 0],
			["maxSends", 11],
			["resendAfterSeconds", -1],
			["resendAfterSeconds", 601],
			["codeTtlSeconds", 600.5],
			["maxSends", "0x3"],
		] as const) {
			expect(
				refusedAt(mfaEmailFactorConfigSchema, { ...EMAIL_DEFAULTS, [key]: value }),
				`${key} ${String(value)}`,
			).not.toEqual([]);
		}
		for (const sendLimit of [
			{ limit: 0, windowSeconds: 3600 },
			{ limit: 5, windowSeconds: 0 },
			{ limit: 5, windowSeconds: 31_536_001 },
		]) {
			expect(
				refusedAt(mfaEmailFactorConfigSchema, { ...EMAIL_DEFAULTS, sendLimit }),
				JSON.stringify(sendLimit),
			).not.toEqual([]);
		}
	});

	it("refuses a subject a header cannot carry, and a body that carries no {code}", () => {
		for (const subject of ["", "   ", "Code\r\nBcc: x@example.com", "a\u0000b", "\ud800"]) {
			expect(
				refusedAt(mfaEmailFactorConfigSchema, { ...EMAIL_DEFAULTS, subject }),
				JSON.stringify(subject),
			).not.toEqual([]);
		}
		for (const body of ["", "Your code is here.", "a\u0000{code}", "{code}\ud800"]) {
			expect(
				refusedAt(mfaEmailFactorConfigSchema, { ...EMAIL_DEFAULTS, body }),
				JSON.stringify(body),
			).not.toEqual([]);
		}
		expect(
			refusedAt(mfaEmailFactorConfigSchema, {
				...EMAIL_DEFAULTS,
				body: "Your code:\n\n\t{code}\n",
			}),
		).toEqual([]);
	});
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

describe("the two factors' modules, declared before their factors are built", () => {
	const base = makeValidAppConfig();
	const configWith = (sections: Record<string, unknown>) => ({
		...base,
		"mfa-email-factor": EMAIL_DEFAULTS,
		"mfa-recovery-code-factor": RECOVERY_DEFAULTS,
		...sections,
	});

	let disposable: { dispose(): Promise<void> } | undefined;
	afterEach(async () => {
		await disposable?.dispose();
		disposable = undefined;
	});

	const boot = async (config: Record<string, unknown>) => {
		const handle = await createApp({
			modules: [mfaEmailFactorModule, mfaRecoveryCodeFactorModule],
			bootstrapComponents: { config, pathResolver: (p: string) => p } as never,
		});
		disposable = handle;
		return handle.components.mfaFactorResolver as MfaFactorResolver;
	};

	const refusal = async (config: Record<string, unknown>): Promise<BootError> => {
		try {
			disposable = await createApp({
				modules: [mfaEmailFactorModule, mfaRecoveryCodeFactorModule],
				bootstrapComponents: { config, pathResolver: (p: string) => p } as never,
			});
		} catch (error) {
			expect(error).toBeInstanceOf(BootError);
			return error as BootError;
		}
		throw new Error("expected the boot to be refused");
	};

	it("are named after their sections, read them at their names, and declare the package's reference.conf", () => {
		expect(mfaEmailFactorModule.name).toBe("mfa-email-factor");
		expect(mfaRecoveryCodeFactorModule.name).toBe("mfa-recovery-code-factor");
		for (const module of [mfaEmailFactorModule, mfaRecoveryCodeFactorModule]) {
			expect(module.section?.at).toBeUndefined();
			expect(module.section?.reference?.href).toBe(new URL(`file://${REFERENCE}`).href);
			expect(module.requires ?? []).toEqual([]);
			expect(module.replicaSafety).toBeUndefined();
		}
		expect(unreadableModuleLeaves([mfaEmailFactorModule, mfaRecoveryCodeFactorModule])).toEqual([]);
	});

	it("boot with their defaults, and add no factor to the resolver", async () => {
		const resolver = await boot(configWith({}));
		expect([...resolver.entries()]).toEqual([]);
	});

	it("refuse the boot for a key their sections do not know, naming its path", async () => {
		for (const [section, value] of [
			["mfa-email-factor", { ...EMAIL_DEFAULTS, maxSend: 3 }],
			["mfa-recovery-code-factor", { ...RECOVERY_DEFAULTS, length: 16 }],
		] as const) {
			const error = await refusal(configWith({ [section]: value }));
			expect(error.reason, section).toBe("config-validation-failed");
			expect(error.message, section).toContain(section);
		}
	});

	it("the email factor's module claims the email kind, and refuses the boot when the factor is switched on", async () => {
		expect(Object.keys(mfaEmailFactorModule.contributes?.mfaFactors ?? {})).toEqual(["email"]);
		const error = await refusal(
			configWith({ "mfa-email-factor": { ...EMAIL_DEFAULTS, enabled: true } }),
		);
		expect(error.reason).toBe("contribute-factory-failed");
		expect(String((error.cause as Error | undefined)?.message)).toContain(
			"mfa-email-factor.enabled",
		);
	});

	it("the recovery-code factor's module contributes nothing", () => {
		expect(mfaRecoveryCodeFactorModule.contributes).toBeUndefined();
		expect(mfaRecoveryCodeFactorModule.provides).toBeUndefined();
	});
});
