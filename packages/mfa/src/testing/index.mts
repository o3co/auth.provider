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
 * `@o3co/auth-provider-mfa/testing`: what another package's tests use of this
 * one, so none writes its sections or seals its data by hand. The three
 * sections its modules read, each as a configuration fragment at the
 * section's name with the reference defaults; a TOTP factor stored as an
 * enrollment leaves it, sealed under a configuration's key ring; and the
 * codes that factor takes. For tests only.
 */

import { randomBytes } from "node:crypto";
import type { MfaFactorRecord, MfaFactorStore, MfaLockoutPolicy } from "@o3co/auth-provider-core";
import { readMfaSettings } from "../config.mjs";
import { createMfaSealing } from "../sealing.mjs";
import { encodeBase32 } from "../totp/base32.mjs";
import { TOTP_FACTOR_KIND } from "../totp/factor.mjs";
import { hotp, type TotpAlgorithm, totpStep } from "../totp/rfc6238.mjs";

/** What {@link mfaConfigForTests} lays over the reference defaults. */
export interface MfaConfigForTestsOptions {
	/** The ring's one key: canonical base64 of 32 bytes. */
	readonly key: string;
	readonly mode?: "off" | "optional" | "required";
	readonly page?: { readonly url: string };
	/** The whole ring, in place of `key`'s. */
	readonly encryptionKeys?: readonly { readonly id?: string; readonly key?: string }[];
	readonly transactionTtlSeconds?: number;
	readonly maxAttemptsPerTransaction?: number;
	readonly lockout?: Partial<MfaLockoutPolicy>;
	readonly rateLimit?: {
		readonly routes?: { readonly limit: number; readonly windowSeconds: number };
	};
	readonly manage?: { readonly maxAgeSeconds: number };
}

/**
 * The MFA module's section, `mfa`, as the package's reference.conf resolves
 * it, with `options` laid over it. The mode is `off` unless given, as there.
 */
export function mfaConfigForTests(options: MfaConfigForTestsOptions) {
	const { key, encryptionKeys, lockout, ...rest } = options;
	return {
		mfa: {
			mode: "off" as "off" | "optional" | "required",
			page: { url: "/mfa" },
			transactionTtlSeconds: 600,
			maxAttemptsPerTransaction: 5,
			rateLimit: { routes: { limit: 60, windowSeconds: 300 } },
			manage: { maxAgeSeconds: 300 },
			...rest,
			encryptionKeys: encryptionKeys?.map((entry) => ({ ...entry })) ?? [{ key }],
			lockout: {
				threshold: 5,
				baseSeconds: 900,
				maxSeconds: 86_400,
				memorySeconds: 86_400,
				weeklyBudget: 10,
				hardLimit: 100,
				trustedBrowsers: 5,
				trustedBrowserDays: 30,
				...lockout,
			},
		},
	};
}

/** What {@link mfaTotpFactorConfigForTests} lays over the reference defaults. */
export interface MfaTotpFactorConfigForTestsOptions {
	readonly enabled?: boolean;
	readonly algorithm?: TotpAlgorithm;
	readonly digits?: number;
	readonly period?: number;
	readonly window?: number;
	readonly issuer?: string;
}

/** The TOTP factor's section, `mfa-totp-factor`, as the package's reference.conf resolves it, with `options` laid over it. */
export function mfaTotpFactorConfigForTests(options: MfaTotpFactorConfigForTestsOptions = {}) {
	return {
		"mfa-totp-factor": {
			enabled: true,
			algorithm: "SHA1" as TotpAlgorithm,
			digits: 6,
			period: 30,
			window: 1,
			...options,
		},
	};
}

/** The recovery-code factor's section, `mfa-recovery-code-factor`, as the package's reference.conf resolves it, with `options` laid over it. */
export function mfaRecoveryCodeFactorConfigForTests(
	options: { readonly enabled?: boolean; readonly count?: number } = {},
) {
	return { "mfa-recovery-code-factor": { enabled: true, count: 10, ...options } };
}

/** What {@link seedTotpFactor} stores. */
export interface SeedTotpFactorOptions {
	/** A configuration holding the MFA module's section: its key ring seals the data. */
	readonly config: unknown;
	readonly factorStore: MfaFactorStore;
	readonly subject: string;
	/** 20 random bytes unless given. */
	readonly secret?: Buffer;
	/** A fresh factor id unless given. */
	readonly id?: string;
	readonly label?: string;
	/** The step the factor's last accepted code was at; 0 unless given. */
	readonly lastUsedStep?: number;
	/** Seal the data to this subject's record instead, as data copied from it would be. */
	readonly sealedFor?: string;
}

/**
 * Stores a TOTP factor for `subject` — SHA1, 6 digits, 30-second steps —
 * its data sealed under the ring of `config`'s MFA section, as an enrollment
 * leaves it. Answers the record stored and the secret.
 */
export async function seedTotpFactor(
	options: SeedTotpFactorOptions,
): Promise<{ readonly record: MfaFactorRecord; readonly secret: Buffer }> {
	const section = (options.config as { mfa?: unknown } | null | undefined)?.mfa;
	const { encryptionKeys } = readMfaSettings(section, { deploymentMode: "unset" });
	const secret = options.secret ?? randomBytes(20);
	const id = options.id ?? randomBytes(16).toString("base64url");
	const record: MfaFactorRecord = {
		id,
		subject: options.subject,
		kind: TOTP_FACTOR_KIND,
		label: options.label,
		binding: "password",
		createdAt: new Date(Date.now() - 86_400_000),
		lastUsedAt: undefined,
		version: 0,
		data: createMfaSealing({ ring: encryptionKeys }).sealFactorData(
			{ subject: options.sealedFor ?? options.subject, id, kind: TOTP_FACTOR_KIND },
			{
				secret: encodeBase32(secret),
				algorithm: "SHA1",
				digits: 6,
				period: 30,
				lastUsedStep: options.lastUsedStep ?? 0,
			},
		),
	};
	await options.factorStore.create(record);
	return { record, secret };
}

/**
 * The code a factor {@link seedTotpFactor} stored takes: RFC 6238 over
 * `secret` at `atMs` (now unless given), `offset` steps away.
 */
export function totpCodeForTests(
	secret: Buffer,
	options: { readonly atMs?: number; readonly offset?: number } = {},
): string {
	const step = totpStep(options.atMs ?? Date.now(), 30) + (options.offset ?? 0);
	return hotp(secret, step, { algorithm: "SHA1", digits: 6 });
}
