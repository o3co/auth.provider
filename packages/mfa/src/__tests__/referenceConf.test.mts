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
 * core's `reference.conf`, resolved and unparsed, as `createApp` is handed
 * it — and the variables that reach them: `MFA_ENCRYPTION_KEY` (the first key
 * of the ring, which has no default), `MFA_TOTP_FACTOR_ENABLED` and
 * `MFA_TOTP_FACTOR_ISSUER`; `mfa.mode`, `off` unless `MFA_MODE` says
 * otherwise; the transaction's life, its attempts and the
 * subject lock, which have no variable (D19); and the two variables still
 * bound at the TOTP factor's old path, which boot refuses.
 */

import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { BootError, createApp } from "@o3co/auth-provider-core";
import { parseFile } from "@o3co/ts.hocon";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
	MFA_DEVELOPMENT_SAMPLE_KEY,
	type MfaSettingsOptions,
	mfaTotpConfigSchema,
	readMfaSettings,
	readMfaTotpSettings,
} from "#/config.mjs";

/** `readMfaSettings` over the `mfa` section of `config`, under the deployment mode a configuration that states none has, unless `options` names one. */
const readSettings = (config: unknown, options: Partial<MfaSettingsOptions> = {}) =>
	readMfaSettings((config as { mfa?: unknown } | undefined)?.mfa, {
		deploymentMode: "unset",
		...options,
	});

import { createMfaSealing } from "#/sealing.mjs";
import { mfaTotpFactorModule } from "#/totp/module.mjs";

const require = createRequire(import.meta.url);
const CORE_REFERENCE = require.resolve("@o3co/auth-provider-core/reference.conf");
const MFA_REFERENCE = fileURLToPath(new URL("../../config/reference.conf", import.meta.url));

/** The three substitutions core's `reference.conf` cannot validate without. */
const REQUIRED_ENV = {
	OAUTH_JWT_SECRET: "mfa-reference-conf.at-least-32-bytes.ok",
	OAUTH_JWT_ISSUER: "https://auth.example",
	SESSION_SECRET: "mfa-reference-conf-session.at-least-32-bytes.ok",
};

/** What a composition root resolves from the two references, as it hands it to `createApp`. */
interface Resolved {
	readonly mfa: { readonly mode?: unknown; readonly factors?: unknown };
	readonly "mfa-totp-factor": Record<string, unknown>;
	readonly oauth: { readonly jwt: { readonly issuer: string } };
}

const resolve = (env: Record<string, string> = {}): Resolved => {
	const options = { env: { ...REQUIRED_ENV, ...env } };
	return parseFile(MFA_REFERENCE, options)
		.withFallback(parseFile(CORE_REFERENCE, options))
		.toObject() as unknown as Resolved;
};

/** The TOTP settings as the factor's module reads them: its section, and the deployment's issuer. */
const totpOf = (config: Resolved) =>
	readMfaTotpSettings(config["mfa-totp-factor"], { issuer: config.oauth.jwt.issuer });

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
		expect(totpOf(config)).toEqual({
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

	it("reads each key of mfa-totp-factor from its variable: MFA_TOTP_FACTOR_ENABLED, _ALGORITHM, _DIGITS, _PERIOD, _WINDOW and _ISSUER", () => {
		const totp = totpOf(
			resolve({
				MFA_TOTP_FACTOR_ENABLED: "false",
				MFA_TOTP_FACTOR_ALGORITHM: "SHA256",
				MFA_TOTP_FACTOR_DIGITS: "8",
				MFA_TOTP_FACTOR_PERIOD: "60",
				MFA_TOTP_FACTOR_WINDOW: "0",
				MFA_TOTP_FACTOR_ISSUER: "Example Co",
			}),
		);
		expect(totp).toEqual({
			enabled: false,
			algorithm: "SHA256",
			digits: 8,
			period: 60,
			window: 0,
			issuer: "Example Co",
		});
	});

	it("binds every variable boot's refusal of the old path names, each at its key's new path; a value written at the old path whole names none", async () => {
		const refusalOf = async (config: unknown) => {
			try {
				const handle = await createApp({
					modules: [mfaTotpFactorModule],
					bootstrapComponents: { config, pathResolver: (p: string) => p } as never,
				});
				await handle.dispose();
			} catch (error) {
				if (error instanceof BootError) return error;
				throw error;
			}
			throw new Error("the boot was not refused");
		};
		const text = readFileSync(MFA_REFERENCE, "utf8");
		for (const key of Object.keys(mfaTotpConfigSchema.shape)) {
			const refused = await refusalOf({
				...resolve(),
				mfa: { factors: { totp: { [key]: "1" } } },
			});
			const [relocated] = (
				refused.details as unknown as { relocated: { to: string; environmentVariable?: string }[] }
			).relocated;
			expect(relocated?.to, key).toBe(`mfa-totp-factor.${key}`);
			const variable = relocated?.environmentVariable ?? "";
			expect(text, key).toContain(`\${?${variable}}`);
			const marked = parseFile(MFA_REFERENCE, { env: { [variable]: "__MARKER__" } }).toObject() as {
				"mfa-totp-factor": Record<string, unknown>;
			};
			expect(marked["mfa-totp-factor"][key], key).toBe("__MARKER__");
		}
		const whole = await refusalOf({ ...resolve(), mfa: { factors: { totp: null } } });
		expect(whole.details).toEqual({
			reason: "config-path-relocated",
			relocated: [{ module: "mfa-totp-factor", from: "mfa.factors.totp", to: "mfa-totp-factor" }],
		});
	});

	it("binds MFA_TOTP_ENABLED and MFA_TOTP_ISSUER at the old path alone, with no default: they feed mfa-totp-factor nothing", () => {
		expect(resolve().mfa.factors).toEqual({ totp: {} });
		const config = resolve({ MFA_TOTP_ENABLED: "false", MFA_TOTP_ISSUER: "Example Co" });
		expect(config.mfa.factors).toEqual({ totp: { enabled: "false", issuer: "Example Co" } });
		expect(totpOf(config)).toMatchObject({ enabled: true, issuer: "auth.example" });
	});

	it("refuses the boot of a composition installing the TOTP factor's module while MFA_TOTP_ENABLED or MFA_TOTP_ISSUER is set, naming the new path and its variable", async () => {
		for (const [variable, key] of [
			["MFA_TOTP_ENABLED", "enabled"],
			["MFA_TOTP_ISSUER", "issuer"],
		] as const) {
			let refused: unknown;
			try {
				const handle = await createApp({
					modules: [mfaTotpFactorModule],
					bootstrapComponents: {
						config: resolve({ [variable]: "Example" }),
						pathResolver: (p: string) => p,
					} as never,
				});
				await handle.dispose();
			} catch (error) {
				refused = error;
			}
			expect(refused, variable).toBeInstanceOf(BootError);
			expect((refused as BootError).reason, variable).toBe("config-path-relocated");
			expect((refused as BootError).details, variable).toEqual({
				reason: "config-path-relocated",
				relocated: [
					{
						module: "mfa-totp-factor",
						from: `mfa.factors.totp.${key}`,
						to: `mfa-totp-factor.${key}`,
						environmentVariable: `MFA_TOTP_FACTOR_${key.toUpperCase()}`,
					},
				],
			});
		}
	});

	it("defaults mfa.mode to off and reads MFA_MODE: this file binds it, and core's reference.conf does not", () => {
		expect(resolve().mfa.mode).toBe("off");
		expect(resolve({ MFA_MODE: "optional" }).mfa.mode).toBe("optional");
		const alone = (env: Record<string, string>) =>
			(parseFile(MFA_REFERENCE, { env }).toObject() as { mfa?: { mode?: unknown } }).mfa?.mode;
		expect(alone({})).toBe("off");
		expect(alone({ MFA_MODE: "required" })).toBe("required");
		const core = parseFile(CORE_REFERENCE, {
			env: { ...REQUIRED_ENV, MFA_MODE: "required" },
		}).toObject();
		expect(core).not.toHaveProperty("mfa");
	});

	it("takes the development sample key through MFA_ENCRYPTION_KEY in development, and refuses it in production", () => {
		vi.stubEnv("NODE_ENV", "development");
		const config = resolve({ MFA_ENCRYPTION_KEY: MFA_DEVELOPMENT_SAMPLE_KEY });
		expect(readSettings(config, { environment: "development" }).encryptionKeys).toHaveLength(1);
		expect(() => readSettings(config, { environment: "production" })).toThrow(/sample key/);
	});
});
