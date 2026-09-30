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
 * The MFA configuration this package reads: the `mfa` section — the key ring
 * `mfa.encryptionKeys`, a transaction's life and attempts, the subject lock —
 * and the TOTP factor's own section, `mfa-totp-factor`. See ADR
 * 2026-09-25-multi-factor-authentication, "Configuration and defaults".
 *
 * - `readMfaSettings` reads the `mfa` section alone: `mfa-totp-factor` is the
 *   TOTP factor's module's (`readMfaTotpSettings`), so a composition without
 *   that module is never refused over it.
 * - The ring is refused empty, with a key that is not canonical base64 of 32
 *   bytes, with a duplicate id (core's sealing rules, under the key it was
 *   read from), and with the published development sample key wherever the
 *   configuration was selected as production or staging, `NODE_ENV` says so,
 *   or `deployment.mode = "multi"`. No refusal quotes a key or an id.
 * - TOTP's parameters are held to their ranges: digits 6-8, period 15-120 s,
 *   window 0-2, SHA1, SHA256 or SHA512; the issuer defaults to the host of
 *   the deployment's issuer.
 * - `mfa.transactionTtlSeconds` is held to 60-1800 seconds and
 *   `mfa.maxAttemptsPerTransaction` to 1-10 (the ADR states neither bound),
 *   and the subject lock, `mfa.lockout`, to core's `checkMfaLockoutPolicy`
 *   under that key: obligations the MFA module refuses a boot for.
 * - The settings say whether the development sample key was accepted, so the
 *   MFA module can say so once at boot.
 */

import { createHmac, randomBytes } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
	MFA_DEVELOPMENT_SAMPLE_KEY,
	type MfaSettingsOptions,
	mfaConfigSchema,
	readMfaSettings,
	readMfaTotpSettings,
} from "#/config.mjs";

/**
 * `readMfaSettings` as the MFA module calls it: over the `mfa` section of
 * `config`, with the deployment mode `config` carries, unless `options`
 * names one.
 */
const readSettings = (config: unknown, options: MfaSettingsOptions = {}) => {
	const shape = config as { mfa?: unknown; deployment?: { mode?: unknown } } | undefined;
	return readMfaSettings(shape?.mfa, { deploymentMode: shape?.deployment?.mode, ...options });
};

const KEY_A = randomBytes(32).toString("base64");
const KEY_B = randomBytes(32).toString("base64");

const TOTP = {
	enabled: true,
	algorithm: "SHA1",
	digits: 6,
	period: 30,
	window: 1,
} as const;

/** The subject lock as `reference.conf` defaults it. */
const LOCKOUT = {
	threshold: 5,
	baseSeconds: 900,
	maxSeconds: 86_400,
	memorySeconds: 86_400,
	weeklyBudget: 10,
	hardLimit: 100,
	trustedBrowsers: 5,
	trustedBrowserDays: 30,
} as const;

/** The transaction's keys, as `reference.conf` defaults them. */
const TRANSACTION = {
	transactionTtlSeconds: 600,
	maxAttemptsPerTransaction: 5,
	lockout: { ...LOCKOUT },
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
		...TRANSACTION,
		...overrides,
	});

/** The deployment's issuer, which an unset TOTP issuer defaults to the host of. */
const ISSUER = "https://auth.example";

/** The TOTP factor's section, `mfa-totp-factor`, with `totp` laid over the defaults. */
const withTotp = (totp: Record<string, unknown>) => ({ ...TOTP, ...totp });

/** `readMfaTotpSettings` over `section`, as the module calls it: with the deployment's issuer. */
const readTotp = (section: unknown, issuer: unknown = ISSUER) =>
	readMfaTotpSettings(section, { issuer });

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
	it("reads the ring in order — the first seals — the transaction's keys and the lock, and no factor's section", () => {
		const settings = readSettings(
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
		expect(settings).not.toHaveProperty("totp");
		expect(settings.transactionTtlSeconds).toBe(600);
		expect(settings.maxAttemptsPerTransaction).toBe(5);
		expect(settings.lockout).toEqual(LOCKOUT);
		expect(settings.developmentSampleKeyAccepted).toBe(false);
	});

	it("refuses a missing section, naming it", () => {
		for (const config of [undefined, {}]) {
			expect(refusal(() => readSettings(config))).toMatch(/^mfa /);
		}
		expect(refusal(() => readTotp(undefined))).toMatch(/^mfa-totp-factor /);
	});

	it("exports the schema of the mfa section it reads: its mode, the ring, the transaction's keys and the lock — no factor's", () => {
		expect(Object.keys(mfaConfigSchema.shape).sort()).toEqual([
			"encryptionKeys",
			"lockout",
			"maxAttemptsPerTransaction",
			"mode",
			"transactionTtlSeconds",
		]);
		expect(mfaConfigSchema.safeParse(valid().mfa).success).toBe(true);
		expect(mfaConfigSchema.safeParse({ ...valid().mfa, mode: "sometimes" }).success).toBe(false);
		expect(mfaConfigSchema.safeParse({}).success).toBe(false);
	});
});

describe("the key ring", () => {
	it("refuses an empty ring, naming MFA_ENCRYPTION_KEY", () => {
		const message = refusal(() => readSettings(valid({ encryptionKeys: [] })));
		expect(message).toContain("mfa.encryptionKeys");
		expect(message).toContain("MFA_ENCRYPTION_KEY");
	});

	it("refuses an entry whose key is not set — the first names MFA_ENCRYPTION_KEY, which feeds it", () => {
		const first = refusal(() => readSettings(valid({ encryptionKeys: [{ id: "k1" }] })));
		expect(first).toContain("mfa.encryptionKeys[0].key");
		expect(first).toContain("MFA_ENCRYPTION_KEY");
		const second = refusal(() =>
			readSettings(
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
			const message = refusal(() => readSettings(valid({ encryptionKeys: [{ id: "k1", key }] })));
			expect(message, key).toContain("mfa.encryptionKeys[0].key");
			expect(message, key).toContain("32 bytes");
			if (key.trim() !== "") expect(message).not.toContain(key.trim());
		}
	});

	it("refuses a duplicate id and an id outside the rule, naming the index and never the id", () => {
		const duplicate = refusal(() =>
			readSettings(
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
			readSettings(valid({ encryptionKeys: [{ id: "has space", key: KEY_A }] })),
		);
		expect(badId).toContain("mfa.encryptionKeys");
		expect(badId).not.toContain("has space");
	});

	it("names an entry written without an id by its key's fingerprint: k and 16 characters of HMAC-SHA-256(key, o3co:mfa:key-id), base64url", () => {
		const fingerprint = (key: string) =>
			`k${createHmac("sha256", Buffer.from(key, "base64")).update("o3co:mfa:key-id").digest("base64url").slice(0, 16)}`;
		const ring = readSettings(
			valid({ encryptionKeys: [{ key: KEY_A }, { id: "named", key: KEY_B }] }),
		).encryptionKeys;
		// A written id is honoured; a missing one is the fingerprint.
		expect(ring.map((entry) => entry.id)).toEqual([fingerprint(KEY_A), "named"]);
		expect(ring[0]?.id).toMatch(/^k[A-Za-z0-9_-]{16}$/);
		// The same key is always named the same; another key otherwise.
		expect(readSettings(valid({ encryptionKeys: [{ key: KEY_A }] })).encryptionKeys[0]?.id).toBe(
			fingerprint(KEY_A),
		);
		expect(fingerprint(KEY_B)).not.toBe(fingerprint(KEY_A));
	});

	it("refuses a fingerprint that collides with a written id, and the same key listed twice, as duplicates", () => {
		const derived = readSettings(valid({ encryptionKeys: [{ key: KEY_A }] })).encryptionKeys[0]
			?.id as string;
		const collision = refusal(() =>
			readSettings(
				valid({
					encryptionKeys: [{ id: derived, key: KEY_B }, { key: KEY_A }],
				}),
			),
		);
		expect(collision).toContain("duplicate");
		expect(collision).toContain("index 1");
		expect(collision).not.toContain(derived);
		expect(
			refusal(() => readSettings(valid({ encryptionKeys: [{ key: KEY_A }, { key: KEY_A }] }))),
		).toContain("duplicate");
	});

	it("refuses one key under two written ids — one AES key cannot be two rotation generations — naming the later entry and quoting neither key nor id", () => {
		const message = refusal(() =>
			readSettings(
				valid({
					encryptionKeys: [
						{ id: "gen-old", key: KEY_A },
						{ id: "gen-mid", key: KEY_B },
						{ id: "gen-new", key: KEY_A },
					],
				}),
			),
		);
		expect(message).toContain("mfa.encryptionKeys[2].key");
		expect(message).toContain("mfa.encryptionKeys[0]");
		expect(message).toContain("duplicate");
		for (const secret of [KEY_A, KEY_B, "gen-old", "gen-new"]) {
			expect(message).not.toContain(secret);
		}
		// Two keys of their own, under two ids, are two generations.
		expect(
			readSettings(
				valid({
					encryptionKeys: [
						{ id: "gen-old", key: KEY_A },
						{ id: "gen-new", key: KEY_B },
					],
				}),
			).encryptionKeys.map((entry) => entry.id),
		).toEqual(["gen-old", "gen-new"]);
	});

	it("refuses a ring that is not a list of { id?, key }", () => {
		for (const encryptionKeys of [
			undefined,
			"k1",
			{ id: "k1", key: KEY_A },
			[{ id: 1, key: KEY_A }],
			[{ id: "k1", key: 1 }],
		]) {
			const message = refusal(() => readSettings(valid({ encryptionKeys })));
			expect(message, JSON.stringify(encryptionKeys)).toContain("mfa.encryptionKeys");
			expect(message).not.toContain(KEY_A);
		}
	});
});

describe("the development sample key", () => {
	const sample = (extra: Record<string, unknown> = {}, second = false) =>
		configWith(
			{
				encryptionKeys: second
					? [
							{ id: "k1", key: KEY_A },
							{ id: "sample", key: MFA_DEVELOPMENT_SAMPLE_KEY },
						]
					: [{ id: "sample", key: MFA_DEVELOPMENT_SAMPLE_KEY }],
				...TRANSACTION,
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
			const settings = readSettings(sample(), environment === undefined ? {} : { environment });
			expect(settings.encryptionKeys[0]?.id, String(environment)).toBe("sample");
		}
	});

	it("is refused where the configuration was selected as production or staging", () => {
		vi.stubEnv("NODE_ENV", "development");
		for (const environment of ["production", "staging"]) {
			const message = refusal(() => readSettings(sample(), { environment }));
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
				const message = refusal(() => readSettings(sample(), options));
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
			const message = refusal(() => readSettings(sample(), { environment }));
			expect(message, JSON.stringify(environment)).toMatch(
				/sample key.*the environment is "(production|staging)"/,
			);
		}
		for (const nodeEnv of ["Production", " staging\n"]) {
			vi.stubEnv("NODE_ENV", nodeEnv);
			expect(
				refusal(() => readSettings(sample())),
				JSON.stringify(nodeEnv),
			).toMatch(/the environment is "(production|staging)"/);
		}
	});

	it("says it was accepted, wherever it sits in the ring, so the MFA module can say so at boot", () => {
		vi.stubEnv("NODE_ENV", "development");
		expect(readSettings(sample()).developmentSampleKeyAccepted).toBe(true);
		expect(readSettings(sample({}, true)).developmentSampleKeyAccepted).toBe(true);
		expect(readSettings(valid()).developmentSampleKeyAccepted).toBe(false);
	});

	it("is accepted where the environment is named prod: an alias does not count as production", () => {
		vi.stubEnv("NODE_ENV", "development");
		expect(readSettings(sample(), { environment: "prod" }).encryptionKeys).toHaveLength(1);
	});

	it("is refused under deployment.mode = multi, in any environment", () => {
		vi.stubEnv("NODE_ENV", "development");
		const message = refusal(() =>
			readSettings(sample({ deployment: { mode: "multi" } }), { environment: "development" }),
		);
		expect(message).toContain('deployment.mode is "multi"');
	});

	it("is refused wherever it sits in the ring, since every key opens", () => {
		vi.stubEnv("NODE_ENV", "development");
		const message = refusal(() => readSettings(sample({}, true), { environment: "production" }));
		expect(message).toContain("mfa.encryptionKeys[1].key");
	});
});

describe("the TOTP factor's section, mfa-totp-factor", () => {
	it("reads the section as the package's reference.conf ships it, the issuer the deployment's host", () => {
		expect(readTotp(withTotp({}))).toEqual({
			enabled: true,
			algorithm: "SHA1",
			digits: 6,
			period: 30,
			window: 1,
			issuer: "auth.example",
		});
	});

	it("holds digits to 6-8, period to 15-120 seconds and window to 0-2 steps: a whole number, or the decimal digits an environment variable carries", () => {
		for (const [key, accepted, refused, range] of [
			[
				"digits",
				[
					[6, 6],
					[8, 8],
					["7", 7],
					[" 8 ", 8],
				],
				[5, 9, 6.5, "6.5", "5", "", "0x7", "7e0", null, true, []],
				"6 to 8",
			],
			[
				"period",
				[
					[15, 15],
					[120, 120],
					["30", 30],
				],
				[14, 121, 0, 30.5, "0x1e", " ", null, true],
				"15 to 120 seconds",
			],
			[
				"window",
				[
					[0, 0],
					[2, 2],
					["0", 0],
				],
				[-1, 3, 1.5, "-1", "", null, true, []],
				"0 to 2 steps",
			],
		] as const) {
			for (const [value, read] of accepted) {
				expect(readTotp(withTotp({ [key]: value }))[key], `${key} ${JSON.stringify(value)}`).toBe(
					read,
				);
			}
			for (const value of refused) {
				const message = refusal(() => readTotp(withTotp({ [key]: value })));
				expect(message, `${key} ${JSON.stringify(value)}`).toContain(
					`mfa-totp-factor.${key} must be a whole number from ${range}`,
				);
			}
		}
	});

	it("takes SHA1, SHA256 and SHA512, spelled so", () => {
		for (const algorithm of ["SHA1", "SHA256", "SHA512"]) {
			expect(readTotp(withTotp({ algorithm })).algorithm).toBe(algorithm);
		}
		for (const algorithm of ["sha1", "SHA-1", "MD5", 1]) {
			expect(refusal(() => readTotp(withTotp({ algorithm })))).toContain(
				"mfa-totp-factor.algorithm",
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
			expect(readTotp(withTotp({ enabled: value })).enabled, String(value)).toBe(enabled);
		}
		expect(refusal(() => readTotp(withTotp({ enabled: "yes" })))).toContain(
			"mfa-totp-factor.enabled",
		);
	});

	it("defaults the issuer to the host of the deployment's issuer it is handed, without its port", () => {
		expect(readTotp(withTotp({})).issuer).toBe("auth.example");
		expect(readTotp(withTotp({}), "https://login.example.com:8443/tenant").issuer).toBe(
			"login.example.com",
		);
		expect(readTotp(withTotp({ issuer: "Example Co" }), "https://x.example").issuer).toBe(
			"Example Co",
		);
	});

	it("refuses an issuer the otpauth label cannot carry, and a default it cannot find, naming MFA_TOTP_FACTOR_ISSUER", () => {
		for (const issuer of ["", "Example:Co", 1]) {
			expect(refusal(() => readTotp(withTotp({ issuer })))).toContain("mfa-totp-factor.issuer");
		}
		for (const deployment of ["not a url", undefined, 1, "https://[2001:db8::1]"]) {
			const message = refusal(() => readMfaTotpSettings(withTotp({}), { issuer: deployment }));
			expect(message, String(deployment)).toContain("mfa-totp-factor.issuer");
			expect(message, String(deployment)).toContain("MFA_TOTP_FACTOR_ISSUER");
		}
	});

	it("resolves the issuer only for a factor that is on: a switched-off one never refuses over a default nothing uses", () => {
		const noHost = "https://[2001:db8::1]";
		const off = readTotp(withTotp({ enabled: false }), noHost);
		expect(off.enabled).toBe(false);
		expect(off.issuer).toBeUndefined();
		// Written, it is kept, and still held to its rule.
		expect(readTotp(withTotp({ enabled: false, issuer: "Example" }), noHost).issuer).toBe(
			"Example",
		);
		expect(refusal(() => readTotp(withTotp({ enabled: false, issuer: "a:b" })))).toContain(
			"mfa-totp-factor.issuer",
		);
		// On, the same configuration is refused.
		expect(refusal(() => readTotp(withTotp({}), noHost))).toContain("MFA_TOTP_FACTOR_ISSUER");
	});

	it("refuses an issuer that is not well-formed text, carries a control character, or is blank", () => {
		for (const issuer of [
			"Ex\uD800ample",
			"\uDC00",
			"Ex\u0000ample",
			"Ex\nample",
			"Ex\tample",
			"Ex\u007Fample",
			"Ex\u0085ample",
			"Ex\u009Fample",
			"   ",
			"\t",
		]) {
			expect(
				refusal(() => readTotp(withTotp({ issuer }))),
				JSON.stringify(issuer),
			).toContain("mfa-totp-factor.issuer");
		}
		for (const issuer of ["Example Co", "Exämple", "例え"]) {
			expect(readTotp(withTotp({ issuer })).issuer).toBe(issuer);
		}
	});

	it("refuses a missing section, naming the reference.conf that carries it", () => {
		const message = refusal(() => readTotp(undefined));
		expect(message).toContain("mfa-totp-factor");
		expect(message).toContain("@o3co/auth-provider-mfa/reference.conf");
	});

	it("is not read by readMfaSettings: the MFA module's settings read the mfa section alone, whatever a factors key there holds", () => {
		for (const factors of [{ totp: { digits: 9 } }, { totp: { enabled: "yes" } }, { totp: {} }]) {
			const settings = readSettings(valid({ factors }));
			expect(settings, JSON.stringify(factors)).not.toHaveProperty("totp");
			expect(settings.encryptionKeys).toHaveLength(1);
		}
	});
});

describe("the transaction's life and attempts, and the lock", () => {
	it("holds mfa.transactionTtlSeconds to 60-1800 seconds, a whole number", () => {
		for (const value of [60, 600, 1800]) {
			expect(readSettings(valid({ transactionTtlSeconds: value })).transactionTtlSeconds).toBe(
				value,
			);
		}
		for (const value of [59, 1801, 0, -600, 600.5, "600", null, undefined]) {
			const message = refusal(() => readSettings(valid({ transactionTtlSeconds: value })));
			expect(message, String(value)).toContain("mfa.transactionTtlSeconds");
			expect(message, String(value)).toContain("60 to 1800 seconds");
		}
	});

	it("holds mfa.maxAttemptsPerTransaction to 1-10, a whole number (the owner's bound; the ADR states none)", () => {
		for (const value of [1, 5, 10]) {
			expect(
				readSettings(valid({ maxAttemptsPerTransaction: value })).maxAttemptsPerTransaction,
			).toBe(value);
		}
		for (const value of [0, 11, 100, -1, 1.5, "5", null, undefined, Number.MAX_SAFE_INTEGER + 1]) {
			const message = refusal(() => readSettings(valid({ maxAttemptsPerTransaction: value })));
			expect(message, String(value)).toContain("mfa.maxAttemptsPerTransaction");
			expect(message, String(value)).toContain("1 to 10");
		}
	});

	it("holds mfa.lockout to core's checkMfaLockoutPolicy, naming the field under mfa.lockout", () => {
		for (const [lockout, field] of [
			[{ ...LOCKOUT, threshold: 0 }, "mfa.lockout.threshold"],
			[{ ...LOCKOUT, weeklyBudget: 2.5 }, "mfa.lockout.weeklyBudget"],
			[{ ...LOCKOUT, trustedBrowsers: "5" }, "mfa.lockout.trustedBrowsers"],
			[{ ...LOCKOUT, hardLimit: 101 }, "mfa.lockout.hardLimit"],
			[{ ...LOCKOUT, threshold: 6, hardLimit: 5 }, "mfa.lockout.threshold"],
			[{ ...LOCKOUT, maxSeconds: 899 }, "mfa.lockout.maxSeconds"],
			[{ ...LOCKOUT, memorySeconds: 10 ** 15 }, "mfa.lockout.memorySeconds"],
			[{ ...LOCKOUT, trustedBrowserDays: undefined }, "mfa.lockout.trustedBrowserDays"],
		] as const) {
			expect(
				refusal(() => readSettings(valid({ lockout }))),
				JSON.stringify(lockout),
			).toContain(field);
		}
	});

	it("refuses a configuration without the lock's section, naming the reference.conf that carries it", () => {
		const { lockout: _lockout, ...withoutLockout } = valid().mfa as Record<string, unknown>;
		const message = refusal(() => readSettings({ ...valid(), mfa: withoutLockout }));
		expect(message).toContain("mfa.lockout");
		expect(message).toContain("@o3co/auth-provider-mfa/reference.conf");
	});
});
