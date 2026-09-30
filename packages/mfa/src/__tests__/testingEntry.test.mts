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
 * The package's testing entry, `@o3co/auth-provider-mfa/testing`: its three
 * sections as configuration fragments the modules accept, a TOTP factor
 * seeded as an enrollment leaves it, and the codes that factor takes.
 */

import { randomBytes } from "node:crypto";
import { createMemoryMfaFactorStore } from "@o3co/auth-provider-core";
import { describe, expect, it } from "vitest";
import { mfaConfigSchema, mfaTotpConfigSchema, readMfaSettings } from "#/config.mjs";
import { mfaRecoveryCodeFactorConfigSchema } from "#/recovery/config.mjs";
import { createMfaSealing } from "#/sealing.mjs";
import {
	mfaConfigForTests,
	mfaRecoveryCodeFactorConfigForTests,
	mfaTotpFactorConfigForTests,
	seedTotpFactor,
	totpCodeForTests,
} from "#/testing/index.mjs";
import { decodeBase32 } from "#/totp/base32.mjs";
import { hotp, totpStep } from "#/totp/rfc6238.mjs";

const KEY = randomBytes(32).toString("base64");

describe("the section builders", () => {
	it("builds the MFA module's section at its name: the reference defaults, the key given, the mode and every key laid over them", () => {
		const fragment = mfaConfigForTests({ key: KEY, mode: "required" });
		expect(Object.keys(fragment)).toEqual(["mfa"]);
		expect(mfaConfigSchema.parse(fragment.mfa)).toMatchObject({
			mode: "required",
			page: { url: "/mfa" },
			transactionTtlSeconds: 600,
			maxAttemptsPerTransaction: 5,
		});
		const settings = readMfaSettings(fragment.mfa, { deploymentMode: "unset" });
		expect(settings.encryptionKeys[0]?.key.equals(Buffer.from(KEY, "base64"))).toBe(true);
		expect(fragment.mfa.rateLimit).toEqual({ routes: { limit: 60, windowSeconds: 300 } });
		expect(
			mfaConfigForTests({ key: KEY, maxAttemptsPerTransaction: 3 }).mfa.maxAttemptsPerTransaction,
		).toBe(3);
		expect(mfaConfigForTests({ key: KEY }).mfa.mode).toBe("off");
	});

	it("builds the TOTP factor's and the recovery-code factor's sections at their names, each its schema's", () => {
		const totp = mfaTotpFactorConfigForTests({ window: 0 });
		expect(Object.keys(totp)).toEqual(["mfa-totp-factor"]);
		expect(mfaTotpConfigSchema.parse(totp["mfa-totp-factor"])).toEqual({
			enabled: true,
			algorithm: "SHA1",
			digits: 6,
			period: 30,
			window: 0,
		});
		const recovery = mfaRecoveryCodeFactorConfigForTests();
		expect(Object.keys(recovery)).toEqual(["mfa-recovery-code-factor"]);
		expect(mfaRecoveryCodeFactorConfigSchema.parse(recovery["mfa-recovery-code-factor"])).toEqual({
			enabled: true,
			count: 10,
		});
	});
});

describe("seedTotpFactor", () => {
	it("stores a TOTP factor sealed under the configuration's key ring, which the ring opens to its secret and parameters", async () => {
		const config = mfaConfigForTests({ key: KEY, mode: "required" });
		const factorStore = createMemoryMfaFactorStore();
		const { record, secret } = await seedTotpFactor({ config, factorStore, subject: "u-alice" });

		expect(await factorStore.list("u-alice")).toEqual([record]);
		expect(record).toMatchObject({ subject: "u-alice", kind: "totp", version: 0 });
		expect(record.id).toMatch(/^[A-Za-z0-9_-]{22}$/);
		const ring = readMfaSettings(config.mfa, { deploymentMode: "unset" }).encryptionKeys;
		const opened = createMfaSealing({ ring }).openFactorData(record, record.data);
		expect(opened.state).toBe("ok");
		if (opened.state !== "ok") return;
		expect(decodeBase32(opened.value.secret as string)?.equals(secret)).toBe(true);
		expect(opened.value).toMatchObject({ algorithm: "SHA1", digits: 6, period: 30, lastUsedStep: 0 });
	});

	it("seals the data to another subject's record when told to, as data copied from it would be", async () => {
		const config = mfaConfigForTests({ key: KEY });
		const factorStore = createMemoryMfaFactorStore();
		const { record } = await seedTotpFactor({
			config,
			factorStore,
			subject: "u-bob",
			sealedFor: "u-alice",
		});
		const ring = readMfaSettings(config.mfa, { deploymentMode: "unset" }).encryptionKeys;
		const sealing = createMfaSealing({ ring });
		expect(sealing.openFactorData(record, record.data)).toEqual({ state: "unreadable" });
		expect(
			sealing.openFactorData({ ...record, subject: "u-alice" }, record.data).state,
		).toBe("ok");
	});
});

describe("totpCodeForTests", () => {
	it("is RFC 6238's code for the secret at the step asked for", () => {
		const secret = randomBytes(20);
		const at = 1_800_000_010_000;
		expect(totpCodeForTests(secret, { atMs: at })).toBe(
			hotp(secret, totpStep(at, 30), { algorithm: "SHA1", digits: 6 }),
		);
		expect(totpCodeForTests(secret, { atMs: at, offset: -1 })).toBe(
			hotp(secret, totpStep(at, 30) - 1, { algorithm: "SHA1", digits: 6 }),
		);
	});
});
