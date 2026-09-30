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
 * The email factor's section, `mfa-email-factor`: its switch, whether a
 * verification adds `mfa`, and a code's life — nothing of the mail, which is
 * the sender's, and no limit on sending. Named after its module, its keys
 * camelCase, its defaults in the package's `reference.conf` alone, each key
 * read from the variable its path names, and an unknown key refused by its
 * name. The module answers no factor while off, requires no sender, and
 * refuses the boot when switched on: this build has no email factor.
 */

import { fileURLToPath } from "node:url";
import { BootError, createApp, type MfaFactorResolver } from "@o3co/auth-provider-core";
import { makeValidAppConfig, unreadableModuleLeaves } from "@o3co/auth-provider-core/testing";
import { parseFile } from "@o3co/ts.hocon";
import { afterEach, describe, expect, it } from "vitest";
import { mfaEmailFactorConfigSchema } from "#/email/config.mjs";
import { mfaEmailFactorModule } from "#/email/module.mjs";
import * as testing from "#/testing/index.mjs";
import { mfaEmailFactorConfigForTests } from "#/testing/index.mjs";

const REFERENCE = new URL("../../config/reference.conf", import.meta.url);

/** The section as the package's reference.conf resolves it under `env`, as a composition root layers it. */
const referenceSection = (env: Record<string, string> = {}): unknown =>
	(parseFile(fileURLToPath(REFERENCE), { env }).toObject() as Record<string, unknown>)[
		mfaEmailFactorModule.name
	];

const DEFAULTS = { enabled: false, addsMfa: false, codeTtlSeconds: 600 };

/** The issues' paths and codes the schema answers for `value`, or none. */
const refusedAt = (value: unknown): string[] =>
	(mfaEmailFactorConfigSchema.safeParse(value).error?.issues ?? []).map(
		(issue) => `${issue.path.map(String).join(".")}:${issue.code}`,
	);

describe("mfa-email-factor, the email factor's section", () => {
	it("defaults to off, adding no mfa, with a code that lives 600 seconds, and holds nothing else", () => {
		expect(mfaEmailFactorConfigSchema.parse(referenceSection())).toEqual(DEFAULTS);
	});

	it("reads each key from the variable its path names", () => {
		expect(
			mfaEmailFactorConfigSchema.parse(
				referenceSection({
					MFA_EMAIL_FACTOR_ENABLED: "true",
					MFA_EMAIL_FACTOR_ADDS_MFA: "true",
					MFA_EMAIL_FACTOR_CODE_TTL_SECONDS: "300",
				}),
			),
		).toEqual({ enabled: true, addsMfa: true, codeTtlSeconds: 300 });
	});

	it("refuses a key it does not know — a subject line, a body or a send limit among them — at the section", () => {
		for (const key of ["subject", "body", "maxSends", "resendAfterSeconds", "sendLimit"]) {
			expect(refusedAt({ ...DEFAULTS, [key]: 1 }), key).toEqual([":unrecognized_keys"]);
		}
	});

	it("holds a code's life to 60-1800 seconds, a whole number", () => {
		for (const codeTtlSeconds of [60, 1800, "600"]) {
			expect(refusedAt({ ...DEFAULTS, codeTtlSeconds }), String(codeTtlSeconds)).toEqual([]);
		}
		for (const codeTtlSeconds of [59, 1801, 600.5, "0x3", ""]) {
			expect(refusedAt({ ...DEFAULTS, codeTtlSeconds }), String(codeTtlSeconds)).not.toEqual([]);
		}
	});
});

describe("mfaEmailFactorConfigForTests, the testing entry's builder", () => {
	it("is on the testing entry", () => {
		expect(Object.keys(testing)).toContain("mfaEmailFactorConfigForTests");
	});

	it("carries the section as the package's reference.conf defaults it, under the module's name, and lays the keys it is given over them", () => {
		expect(mfaEmailFactorConfigForTests()).toEqual({
			[mfaEmailFactorModule.name]: mfaEmailFactorConfigSchema.parse(referenceSection()),
		});
		expect(mfaEmailFactorConfigForTests({ enabled: true })).toEqual({
			[mfaEmailFactorModule.name]: { ...DEFAULTS, enabled: true },
		});
	});
});

describe("mfaEmailFactorModule, which declares the section", () => {
	let disposable: { dispose(): Promise<void> } | undefined;
	afterEach(async () => {
		await disposable?.dispose();
		disposable = undefined;
	});

	/** Boots the module over core's valid configuration with `section`: the handle, or the refusal. */
	const boot = async (
		section: Record<string, unknown>,
	): Promise<{ readonly resolver?: MfaFactorResolver; readonly refused?: unknown }> => {
		try {
			const handle = await createApp({
				modules: [mfaEmailFactorModule],
				bootstrapComponents: {
					config: { ...makeValidAppConfig(), ...section },
					pathResolver: (p: string) => p,
				} as never,
			});
			disposable = handle;
			return { resolver: handle.components.mfaFactorResolver as MfaFactorResolver };
		} catch (error) {
			return { refused: error };
		}
	};

	it("is named after its section, reads it at its name, declares the package's reference.conf, and requires nothing: no mail sender either", () => {
		expect(mfaEmailFactorModule.name).toBe("mfa-email-factor");
		expect(mfaEmailFactorModule.section?.at).toBeUndefined();
		expect(mfaEmailFactorModule.section?.reference?.href).toBe(REFERENCE.href);
		expect(mfaEmailFactorModule.requires ?? []).toEqual([]);
		expect(mfaEmailFactorModule.optional ?? []).toEqual([]);
		expect(mfaEmailFactorModule.provides).toBeUndefined();
		expect(mfaEmailFactorModule.replicaSafety).toBeUndefined();
		expect(unreadableModuleLeaves([mfaEmailFactorModule])).toEqual([]);
	});

	it("claims the email kind, and while off, with no mail sender installed, boots and adds no factor", async () => {
		expect(Object.keys(mfaEmailFactorModule.contributes?.mfaFactors ?? {})).toEqual(["email"]);
		const { resolver, refused } = await boot(mfaEmailFactorConfigForTests());
		expect(refused).toBeUndefined();
		expect(resolver?.get("email")).toBeUndefined();
		expect([...(resolver?.entries() ?? [])]).toEqual([]);
	});

	it("refuses the boot when switched on, naming the key and its variable", async () => {
		const { refused } = await boot(mfaEmailFactorConfigForTests({ enabled: true }));
		expect(refused).toBeInstanceOf(BootError);
		expect(String((refused as BootError).message)).toContain("mfa-email-factor.enabled");
		expect(String((refused as BootError).message)).toContain("MFA_EMAIL_FACTOR_ENABLED");
	});

	it("refuses the boot for a key its section does not know, naming the section and the key", async () => {
		const { refused } = await boot(
			mfaEmailFactorConfigForTests({ subject: "Your sign-in code" } as never),
		);
		expect(refused).toBeInstanceOf(BootError);
		expect((refused as BootError).reason).toBe("config-validation-failed");
		expect((refused as BootError).message).toContain(
			"mfa-email-factor: has a key it does not know: subject",
		);
	});
});
