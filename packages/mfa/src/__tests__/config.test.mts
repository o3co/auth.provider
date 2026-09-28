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
 * The MFA configuration this package reads (the MFA ADR's D11, D19, D20,
 * D22): the key ring `mfa.encryptionKeys` and the TOTP factor's
 * `mfa.factors.totp`.
 *
 * - The ring is refused empty, with a key that is not canonical base64 of 32
 *   bytes, with a duplicate id (core's sealing rules, under the key it was
 *   read from), and — #473's rule — with the published development sample key
 *   wherever the configuration was selected as production or staging,
 *   `NODE_ENV` says so, or `deployment.mode = "multi"`. No refusal quotes a
 *   key or an id.
 * - TOTP's parameters are held to their ranges: digits 6-8, period 15-120 s,
 *   window 0-2 (D22 states the window's), SHA1, SHA256 or SHA512; the issuer
 *   defaults to the host `oauth.jwt.issuer` names.
 */

import { randomBytes } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
	MFA_DEVELOPMENT_SAMPLE_KEY,
	mfaConfigSchema,
	readMfaSettings,
	readMfaTotpSettings,
} from "#/config.mjs";

const KEY_A = randomBytes(32).toString("base64");
const KEY_B = randomBytes(32).toString("base64");

const TOTP = {
	enabled: true,
	algorithm: "SHA1",
	digits: 6,
	period: 30,
	window: 1,
} as const;

/** A configuration as the composition root hands it, with `mfa` as given. */
const configWith = (mfa: Record<string, unknown>, extra: Record<string, unknown> = {}) => ({
	oauth: { jwt: { issuer: "https://auth.example" } },
	deployment: { mode: "single" },
	...extra,
	mfa: { mode: "off", ...mfa },
});

const valid = (overrides: Record<string, unknown> = {}) =>
	configWith({
		encryptionKeys: [{ id: "k1", key: KEY_A }],
		factors: { totp: { ...TOTP } },
		...overrides,
	});

const withTotp = (totp: Record<string, unknown>) =>
	valid({ factors: { totp: { ...TOTP, ...totp } } });

/** The refusal `read` throws, as a RangeError. */
function refusal(read: () => unknown): string {
	try {
		read();
	} catch (error) {
		expect(error).toBeInstanceOf(RangeError);
		return (error as Error).message;
	}
	throw new Error("expected a refusal");
}

afterEach(() => {
	vi.unstubAllEnvs();
});

describe("the MFA settings this package reads", () => {
	it("reads the ring in order — the first seals — and the TOTP parameters", () => {
		const settings = readMfaSettings(
			valid({
				encryptionKeys: [
					{ id: "k2", key: KEY_B },
					{ id: "k1", key: KEY_A },
				],
			}),
		);
		expect(settings.encryptionKeys.map((entry) => entry.id)).toEqual(["k2", "k1"]);
		expect(settings.encryptionKeys[0]?.key.equals(Buffer.from(KEY_B, "base64"))).toBe(true);
		expect(settings.encryptionKeys[1]?.key.equals(Buffer.from(KEY_A, "base64"))).toBe(true);
		expect(settings.totp).toEqual({
			enabled: true,
			algorithm: "SHA1",
			digits: 6,
			period: 30,
			window: 1,
			issuer: "auth.example",
		});
	});

	it("refuses a configuration without an mfa section, naming it", () => {
		for (const config of [undefined, {}]) {
			expect(refusal(() => readMfaSettings(config))).toMatch(/^mfa /);
			expect(refusal(() => readMfaTotpSettings(config))).toMatch(/^mfa /);
		}
	});

	it("exports the schema of the section it reads", () => {
		expect(mfaConfigSchema.safeParse(valid().mfa).success).toBe(true);
		expect(mfaConfigSchema.safeParse({}).success).toBe(false);
	});
});

describe("the key ring (D11, D20)", () => {
	it("refuses an empty ring, naming MFA_ENCRYPTION_KEY", () => {
		const message = refusal(() => readMfaSettings(valid({ encryptionKeys: [] })));
		expect(message).toContain("mfa.encryptionKeys");
		expect(message).toContain("MFA_ENCRYPTION_KEY");
	});

	it("refuses an entry whose key is not set — the first names MFA_ENCRYPTION_KEY, which feeds it", () => {
		const first = refusal(() => readMfaSettings(valid({ encryptionKeys: [{ id: "k1" }] })));
		expect(first).toContain("mfa.encryptionKeys[0].key");
		expect(first).toContain("MFA_ENCRYPTION_KEY");
		const second = refusal(() =>
			readMfaSettings(
				valid({
					encryptionKeys: [{ id: "k1", key: KEY_A }, { id: "k2" }],
				}),
			),
		);
		expect(second).toContain("mfa.encryptionKeys[1].key");
	});

	it("refuses a key that is not canonical base64 of 32 bytes, naming the entry and quoting nothing", () => {
		for (const key of [
			randomBytes(16).toString("base64"),
			randomBytes(33).toString("base64"),
			`${KEY_A}\n`,
			` ${KEY_A}`,
			// Unpadded: base64 of 32 bytes ends in one "=".
			KEY_A.replace(/=+$/, ""),
			randomBytes(32).toString("hex"),
			"",
		]) {
			const message = refusal(() =>
				readMfaSettings(valid({ encryptionKeys: [{ id: "k1", key }] })),
			);
			expect(message, key).toContain("mfa.encryptionKeys[0].key");
			expect(message, key).toContain("32 bytes");
			if (key.trim() !== "") expect(message).not.toContain(key.trim());
		}
	});

	it("refuses a duplicate id and an id outside the rule, naming the index and never the id", () => {
		const duplicate = refusal(() =>
			readMfaSettings(
				valid({
					encryptionKeys: [
						{ id: "same-id", key: KEY_A },
						{ id: "same-id", key: KEY_B },
					],
				}),
			),
		);
		expect(duplicate).toContain("mfa.encryptionKeys");
		expect(duplicate).toContain("duplicate");
		expect(duplicate).toContain("index 1");
		expect(duplicate).not.toContain("same-id");
		const badId = refusal(() =>
			readMfaSettings(valid({ encryptionKeys: [{ id: "has space", key: KEY_A }] })),
		);
		expect(badId).toContain("mfa.encryptionKeys");
		expect(badId).not.toContain("has space");
	});

	it("refuses a ring that is not a list of { id, key }", () => {
		for (const encryptionKeys of [
			undefined,
			"k1",
			{ id: "k1", key: KEY_A },
			[{ key: KEY_A }],
			[{ id: 1, key: KEY_A }],
			[{ id: "k1", key: 1 }],
		]) {
			const message = refusal(() => readMfaSettings(valid({ encryptionKeys })));
			expect(message, JSON.stringify(encryptionKeys)).toContain("mfa.encryptionKeys");
			expect(message).not.toContain(KEY_A);
		}
	});
});

describe("the development sample key (D11, #473's rule)", () => {
	const sample = (extra: Record<string, unknown> = {}, second = false) =>
		configWith(
			{
				encryptionKeys: second
					? [
							{ id: "k1", key: KEY_A },
							{ id: "sample", key: MFA_DEVELOPMENT_SAMPLE_KEY },
						]
					: [{ id: "sample", key: MFA_DEVELOPMENT_SAMPLE_KEY }],
				factors: { totp: { ...TOTP } },
			},
			extra,
		);

	it("is a key the ring accepts: canonical base64 of 32 bytes", () => {
		expect(Buffer.from(MFA_DEVELOPMENT_SAMPLE_KEY, "base64")).toHaveLength(32);
		expect(Buffer.from(MFA_DEVELOPMENT_SAMPLE_KEY, "base64").toString("base64")).toBe(
			MFA_DEVELOPMENT_SAMPLE_KEY,
		);
	});

	it("is accepted in development: an environment and NODE_ENV that are neither production nor staging, one replica", () => {
		vi.stubEnv("NODE_ENV", "development");
		for (const environment of [undefined, "development", "test", "local"]) {
			const settings = readMfaSettings(sample(), environment === undefined ? {} : { environment });
			expect(settings.encryptionKeys[0]?.id, String(environment)).toBe("sample");
		}
	});

	it("is refused where the configuration was selected as production or staging", () => {
		vi.stubEnv("NODE_ENV", "development");
		for (const environment of ["production", "staging"]) {
			const message = refusal(() => readMfaSettings(sample(), { environment }));
			expect(message).toContain("mfa.encryptionKeys[0].key");
			expect(message).toContain("sample key");
			expect(message).toContain(`the environment is "${environment}"`);
			expect(message).toContain("MFA_ENCRYPTION_KEY");
			expect(message).not.toContain(MFA_DEVELOPMENT_SAMPLE_KEY);
		}
	});

	it("is refused where NODE_ENV is production or staging, whatever environment is passed", () => {
		for (const nodeEnv of ["production", "staging"]) {
			vi.stubEnv("NODE_ENV", nodeEnv);
			for (const options of [{}, { environment: "development" }]) {
				const message = refusal(() => readMfaSettings(sample(), options));
				expect(message).toContain(`the environment is "${nodeEnv}"`);
			}
		}
	});

	it("reads the environment's name whatever its case and the whitespace around it", () => {
		vi.stubEnv("NODE_ENV", "development");
		for (const environment of [
			"Production",
			" production",
			"production\n",
			"Staging",
			"STAGING",
			"\tstaging ",
		]) {
			const message = refusal(() => readMfaSettings(sample(), { environment }));
			expect(message, JSON.stringify(environment)).toMatch(
				/sample key.*the environment is "(production|staging)"/,
			);
		}
		for (const nodeEnv of ["Production", " staging\n"]) {
			vi.stubEnv("NODE_ENV", nodeEnv);
			expect(
				refusal(() => readMfaSettings(sample())),
				JSON.stringify(nodeEnv),
			).toMatch(/the environment is "(production|staging)"/);
		}
	});

	it("keeps #473's two names: an alias such as prod is not one of them", () => {
		vi.stubEnv("NODE_ENV", "development");
		expect(readMfaSettings(sample(), { environment: "prod" }).encryptionKeys).toHaveLength(1);
	});

	it("is refused under deployment.mode = multi, in any environment", () => {
		vi.stubEnv("NODE_ENV", "development");
		const message = refusal(() =>
			readMfaSettings(sample({ deployment: { mode: "multi" } }), { environment: "development" }),
		);
		expect(message).toContain('deployment.mode is "multi"');
	});

	it("is refused wherever it sits in the ring, since every key opens", () => {
		vi.stubEnv("NODE_ENV", "development");
		const message = refusal(() => readMfaSettings(sample({}, true), { environment: "production" }));
		expect(message).toContain("mfa.encryptionKeys[1].key");
	});
});

describe("the TOTP factor's parameters (D19, D22)", () => {
	it("holds digits to 6-8, period to 15-120 seconds and window to 0-2 steps", () => {
		for (const [key, accepted, refused] of [
			["digits", [6, 7, 8], [5, 9, 6.5, "6", null]],
			["period", [15, 30, 120], [14, 121, 0, 30.5, "30"]],
			["window", [0, 1, 2], [-1, 3, 1.5, "1"]],
		] as const) {
			for (const value of accepted) {
				expect(readMfaTotpSettings(withTotp({ [key]: value }))[key], `${key} ${value}`).toBe(value);
			}
			for (const value of refused) {
				const message = refusal(() => readMfaTotpSettings(withTotp({ [key]: value })));
				expect(message, `${key} ${String(value)}`).toContain(`mfa.factors.totp.${key}`);
			}
		}
	});

	it("takes SHA1, SHA256 and SHA512, spelled so", () => {
		for (const algorithm of ["SHA1", "SHA256", "SHA512"]) {
			expect(readMfaTotpSettings(withTotp({ algorithm })).algorithm).toBe(algorithm);
		}
		for (const algorithm of ["sha1", "SHA-1", "MD5", 1]) {
			expect(refusal(() => readMfaTotpSettings(withTotp({ algorithm })))).toContain(
				"mfa.factors.totp.algorithm",
			);
		}
	});

	it("reads enabled as every switch is read from the environment, and refuses anything else", () => {
		for (const [value, enabled] of [
			[true, true],
			["true", true],
			["1", true],
			[false, false],
			["false", false],
			["0", false],
			["", false],
		] as const) {
			expect(readMfaTotpSettings(withTotp({ enabled: value })).enabled, String(value)).toBe(
				enabled,
			);
		}
		expect(refusal(() => readMfaTotpSettings(withTotp({ enabled: "yes" })))).toContain(
			"mfa.factors.totp.enabled",
		);
	});

	it("defaults the issuer to the host oauth.jwt.issuer names, without its port", () => {
		expect(readMfaTotpSettings(withTotp({})).issuer).toBe("auth.example");
		expect(
			readMfaTotpSettings({
				...withTotp({}),
				oauth: { jwt: { issuer: "https://login.example.com:8443/tenant" } },
			}).issuer,
		).toBe("login.example.com");
		expect(readMfaTotpSettings(withTotp({ issuer: "Example Co" })).issuer).toBe("Example Co");
	});

	it("refuses an issuer the otpauth label cannot carry, and a default it cannot find", () => {
		for (const issuer of ["", "Example:Co", 1]) {
			expect(refusal(() => readMfaTotpSettings(withTotp({ issuer })))).toContain(
				"mfa.factors.totp.issuer",
			);
		}
		for (const oauth of [{ jwt: { issuer: "not a url" } }, { jwt: {} }, undefined]) {
			const message = refusal(() => readMfaTotpSettings({ ...withTotp({}), oauth }));
			expect(message).toContain("mfa.factors.totp.issuer");
			expect(message).toContain("MFA_TOTP_ISSUER");
		}
	});

	it("refuses a configuration without the section, naming the reference.conf that carries it", () => {
		for (const mfa of [{ mode: "off" }, { factors: {} }]) {
			const message = refusal(() => readMfaTotpSettings({ ...valid(), mfa }));
			expect(message).toContain("mfa.factors");
			expect(message).toContain("@o3co/auth-provider-mfa/reference.conf");
		}
	});

	it("reads the factor's section without the key ring, which the factor never holds", () => {
		expect(readMfaTotpSettings(configWith({ factors: { totp: { ...TOTP } } })).algorithm).toBe(
			"SHA1",
		);
	});

	it("is read by readMfaSettings too, with the same refusals", () => {
		expect(refusal(() => readMfaSettings(withTotp({ digits: 9 })))).toContain(
			"mfa.factors.totp.digits",
		);
	});
});
