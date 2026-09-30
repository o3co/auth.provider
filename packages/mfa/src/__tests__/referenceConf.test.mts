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
 * The package's `reference.conf` (the MFA ADR's D19): the defaults of the
 * keys this package reads, layered as a composition root layers it — over
 * core's `reference.conf`, through core's `AppConfigSchema` — and the
 * variables that reach them: `MFA_ENCRYPTION_KEY` (the first key of the ring,
 * which has no default), `MFA_TOTP_ENABLED` and `MFA_TOTP_ISSUER`; and the
 * transaction's life, its attempts and the subject lock, which have no
 * variable (D19).
 */

import { randomBytes } from "node:crypto";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { AppConfigSchema } from "@o3co/auth-provider-core";
import { parseFile } from "@o3co/ts.hocon";
import { validate } from "@o3co/ts.hocon/zod";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
	MFA_DEVELOPMENT_SAMPLE_KEY,
	type MfaSettingsOptions,
	readMfaSettings,
	readMfaTotpSettings,
} from "#/config.mjs";

/** `readMfaSettings` under the deployment mode a configuration that states none has, unless `options` names one. */
const readSettings = (config: unknown, options: Partial<MfaSettingsOptions> = {}) =>
	readMfaSettings(config, { deploymentMode: "unset", ...options });

import { createMfaSealing } from "#/sealing.mjs";

const require = createRequire(import.meta.url);
const CORE_REFERENCE = require.resolve("@o3co/auth-provider-core/reference.conf");
const MFA_REFERENCE = fileURLToPath(new URL("../../config/reference.conf", import.meta.url));

/** The three substitutions core's `reference.conf` cannot validate without. */
const REQUIRED_ENV = {
	OAUTH_JWT_SECRET: "mfa-reference-conf.at-least-32-bytes.ok",
	OAUTH_JWT_ISSUER: "https://auth.example",
	SESSION_SECRET: "mfa-reference-conf-session.at-least-32-bytes.ok",
};

const resolve = (env: Record<string, string> = {}) => {
	const options = { env: { ...REQUIRED_ENV, ...env } };
	return validate(
		parseFile(MFA_REFERENCE, options).withFallback(parseFile(CORE_REFERENCE, options)),
		AppConfigSchema,
	);
};

afterEach(() => {
	vi.unstubAllEnvs();
});

describe("the package's reference.conf", () => {
	it("gives the ring no key: without MFA_ENCRYPTION_KEY, the settings are refused, naming it", () => {
		expect(() => readSettings(resolve())).toThrow(/MFA_ENCRYPTION_KEY/);
	});

	it("puts MFA_ENCRYPTION_KEY first in the ring, and defaults TOTP to on, SHA1, 6 digits, 30 s, a window of 1, the issuer's host", () => {
		const key = randomBytes(32).toString("base64");
		const config = resolve({ MFA_ENCRYPTION_KEY: key });
		const settings = readSettings(config);
		expect(settings.encryptionKeys).toHaveLength(1);
		expect(settings.encryptionKeys[0]?.key.equals(Buffer.from(key, "base64"))).toBe(true);
		expect(readMfaTotpSettings(config)).toEqual({
			enabled: true,
			algorithm: "SHA1",
			digits: 6,
			period: 30,
			window: 1,
			issuer: "auth.example",
		});
	});

	it("names the key MFA_ENCRYPTION_KEY feeds by its fingerprint, so a key changed in place leaves what the old one sealed key_unavailable, naming it", () => {
		const record = { subject: "u-alice", id: "f-1", kind: "totp" };
		const oldKey = randomBytes(32).toString("base64");
		const before = readSettings(resolve({ MFA_ENCRYPTION_KEY: oldKey })).encryptionKeys;
		const sealed = createMfaSealing({ ring: before }).sealFactorData(record, { lastUsedStep: 1 });
		const after = readSettings(
			resolve({ MFA_ENCRYPTION_KEY: randomBytes(32).toString("base64") }),
		).encryptionKeys;
		expect(after[0]?.id).not.toBe(before[0]?.id);
		// Not unreadable, which no key would cure: the operator is told which key to put back.
		expect(createMfaSealing({ ring: after }).openFactorData(record, sealed)).toEqual({
			state: "key_unavailable",
			keyId: before[0]?.id,
		});
		expect(
			createMfaSealing({ ring: [...after, ...before] }).openFactorData(record, sealed),
		).toMatchObject({ state: "ok" });
		// Read again, the same key has the same name.
		expect(readSettings(resolve({ MFA_ENCRYPTION_KEY: oldKey })).encryptionKeys[0]?.id).toBe(
			before[0]?.id,
		);
	});

	it("defaults a transaction to 600 seconds and 5 attempts, and the lock to a threshold of 5, 900 s base, 86400 s max and memory, a weekly budget of 10, a hard limit of 100, 5 trusted browsers for 30 days", () => {
		const settings = readSettings(
			resolve({ MFA_ENCRYPTION_KEY: randomBytes(32).toString("base64") }),
		);
		expect(settings.transactionTtlSeconds).toBe(600);
		expect(settings.maxAttemptsPerTransaction).toBe(5);
		expect(settings.lockout).toEqual({
			threshold: 5,
			baseSeconds: 900,
			maxSeconds: 86_400,
			memorySeconds: 86_400,
			weeklyBudget: 10,
			hardLimit: 100,
			trustedBrowsers: 5,
			trustedBrowserDays: 30,
		});
	});

	it("reads MFA_TOTP_ENABLED and MFA_TOTP_ISSUER", () => {
		const totp = readMfaTotpSettings(
			resolve({ MFA_TOTP_ENABLED: "false", MFA_TOTP_ISSUER: "Example Co" }),
		);
		expect(totp.enabled).toBe(false);
		expect(totp.issuer).toBe("Example Co");
	});

	it("keeps core's mfa.mode beside the package's keys", () => {
		expect(resolve().mfa.mode).toBe("off");
		expect(resolve({ MFA_MODE: "optional" }).mfa.mode).toBe("optional");
	});

	it("takes the development sample key through MFA_ENCRYPTION_KEY in development, and refuses it in production", () => {
		vi.stubEnv("NODE_ENV", "development");
		const config = resolve({ MFA_ENCRYPTION_KEY: MFA_DEVELOPMENT_SAMPLE_KEY });
		expect(readSettings(config, { environment: "development" }).encryptionKeys).toHaveLength(1);
		expect(() => readSettings(config, { environment: "production" })).toThrow(/sample key/);
	});
});
