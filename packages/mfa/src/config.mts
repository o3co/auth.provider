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
 * The `mfa` configuration this package reads (the MFA ADR's D11, D19, D20,
 * D22), and the refusals D20 gives the MFA configuration: `mfa.mode` is
 * core's; the rest of the section — which core's schema passes through — is
 * read here.
 *
 * - `mfa.encryptionKeys`, the key ring every factor's data is sealed under:
 *   each key canonical base64 of 32 bytes, named by its id or — an entry
 *   written without one — by its fingerprint, the ring checked by core's sealing
 *   rule under the key it was read from (no empty ring, no duplicate id, every
 *   id within the rule), every refusal naming the entry by index and quoting
 *   neither a key nor an id. The published development sample key is refused
 *   by #473's rule: where the environment the configuration was selected by,
 *   or `NODE_ENV`, is `production` or `staging`, and under
 *   `deployment.mode = "multi"`.
 * - `mfa.factors.totp`: the parameters of a new enrollment (digits 6-8,
 *   period 15-120 s — the step-8 owner decision, the ADR stating no bounds
 *   for either — SHA1, SHA256 or SHA512), the window every verification
 *   allows (0-2, D22), and the issuer an authenticator app shows, defaulting
 *   — for a factor that is on — to the host `oauth.jwt.issuer` names. Read on
 *   its own too, for the factor, which never holds a key and reads none of
 *   the keys below.
 * - `mfa.transactionTtlSeconds`, a transaction's life, 60-1800 seconds (the
 *   step-8 owner decision; the ADR states no bounds), from which every
 *   `expiresAtMs` is derived and nothing else; `mfa.maxAttemptsPerTransaction`,
 *   a positive whole number, what the store's `reserveAttempt` takes; and
 *   `mfa.lockout`, D21's subject lock, held to core's `checkMfaLockoutPolicy`
 *   under that key — step 3's obligations, refused at boot (D8, D21).
 *
 * No default is written here: they live in `config/reference.conf` (ADR
 * 2026-04-30). A refusal is a `RangeError` whose message starts with the key.
 */

import { createHmac } from "node:crypto";
import {
	checkMfaLockoutPolicy,
	checkSealingKeyRing,
	coerceBooleanFromEnv,
	decodeSealingKey,
	type MfaLockoutPolicy,
	SEALING_KEY_BYTES,
	type SealingKeyRing,
} from "@o3co/auth-provider-core";
import { z } from "zod";
import type { TotpFactorSettings } from "./totp/factor.mjs";
import { TOTP_ALGORITHMS } from "./totp/rfc6238.mjs";
import { MFA_TRANSACTION_TTL_SECONDS } from "./transactions.mjs";

/**
 * A published key for development only — canonical base64 of 32 bytes, the
 * ASCII text `o3co:mfa:development-sample-key!` — which a development
 * configuration may carry in place of `MFA_ENCRYPTION_KEY` (D11). Everyone
 * holds it, so data sealed under it is sealed from nobody: the settings
 * refuse it wherever the configuration was selected as production or
 * staging, `NODE_ENV` is either, or `deployment.mode` is `"multi"`.
 */
export const MFA_DEVELOPMENT_SAMPLE_KEY = "bzNjbzptZmE6ZGV2ZWxvcG1lbnQtc2FtcGxlLWtleSE=";

const SECTION_MISSING =
	"is missing: layer @o3co/auth-provider-mfa/reference.conf beneath the composition's configuration";

const wholeNumber = (min: number, max: number, unit: string) => {
	const error = `must be a whole number from ${min} to ${max}${unit}`;
	return z.number({ error }).int({ error }).min(min, { error }).max(max, { error });
};

const ISSUER_RULE =
	"must be well-formed text, not blank, with no control character and no colon — the otpauth label puts one between the issuer and the account";

/** Whether `text` carries a C0 control character, DEL or a C1 control character. */
function hasControlCharacter(text: string): boolean {
	for (let index = 0; index < text.length; index++) {
		const code = text.charCodeAt(index);
		if (code <= 0x1f || (code >= 0x7f && code <= 0x9f)) return true;
	}
	return false;
}

/** An issuer the otpauth label can carry, and an authenticator app can show. */
const isShowableIssuer = (issuer: string): boolean =>
	issuer.isWellFormed() &&
	issuer.trim() !== "" &&
	!hasControlCharacter(issuer) &&
	!issuer.includes(":");

/** `mfa.factors.totp`: the TOTP factor's switch and parameters (D19). */
export const mfaTotpConfigSchema = z.object(
	{
		enabled: coerceBooleanFromEnv,
		algorithm: z.enum(TOTP_ALGORITHMS, {
			error: `must be one of ${TOTP_ALGORITHMS.map((name) => `"${name}"`).join(", ")}`,
		}),
		digits: wholeNumber(6, 8, ""),
		period: wholeNumber(15, 120, " seconds"),
		window: wholeNumber(0, 2, " steps"),
		issuer: z
			.string({ error: ISSUER_RULE })
			.refine(isShowableIssuer, { error: ISSUER_RULE })
			.optional(),
	},
	{ error: SECTION_MISSING },
);

const RING_SHAPE = "must be a list of { id?, key } entries";

const factorsSchema = z.object({ totp: mfaTotpConfigSchema }, { error: SECTION_MISSING });

const POSITIVE_WHOLE = "must be a positive whole number";
const positiveWhole = z
	.number({ error: POSITIVE_WHOLE })
	.int({ error: POSITIVE_WHOLE })
	.positive({ error: POSITIVE_WHOLE });

/**
 * `mfa.lockout`, D21's subject lock: each field a positive whole number here;
 * how the fields relate — `threshold` at most `hardLimit`, `hardLimit` at
 * most NIST's cap, `maxSeconds` at least `baseSeconds`, every duration within
 * the Date range — is core's `checkMfaLockoutPolicy`, which `readMfaSettings`
 * applies under the key.
 */
const lockoutSchema = z.object(
	{
		threshold: positiveWhole,
		baseSeconds: positiveWhole,
		maxSeconds: positiveWhole,
		memorySeconds: positiveWhole,
		weeklyBudget: positiveWhole,
		hardLimit: positiveWhole,
		trustedBrowsers: positiveWhole,
		trustedBrowserDays: positiveWhole,
	},
	{ error: SECTION_MISSING },
);

/**
 * The shapes of the `mfa` keys this package reads — the key ring, the
 * factors, a transaction's life and attempts, and the subject lock (D19) —
 * with TOTP's ranges and the transaction's. The ring's refusals (a key that
 * is not 32 bytes, an empty ring, a duplicate id), the sample key's and how
 * the lock's fields relate are not the schema's: `readMfaSettings` makes
 * them, where the keys are decoded, the environment is known and core's rule
 * is applied, and they are what D20 calls the MFA config schema's.
 * `mfa.mode` is core's.
 */
export const mfaConfigSchema = z.object(
	{
		encryptionKeys: z.array(
			z.object(
				{
					id: z.string({ error: "must be a string, or left out" }).optional(),
					key: z.string({ error: "must be canonical base64 of 32 bytes" }).optional(),
				},
				{ error: RING_SHAPE },
			),
			{ error: RING_SHAPE },
		),
		factors: factorsSchema,
		transactionTtlSeconds: wholeNumber(
			MFA_TRANSACTION_TTL_SECONDS.min,
			MFA_TRANSACTION_TTL_SECONDS.max,
			" seconds",
		),
		maxAttemptsPerTransaction: positiveWhole,
		lockout: lockoutSchema,
	},
	{ error: SECTION_MISSING },
);

/**
 * `mfa.factors.totp` as the factor and its module read it: the switch and the
 * parameters, and — for a factor that is on — the issuer resolved. A
 * switched-off factor keeps only an issuer written for it: the default is not
 * derived, so a factor nothing uses never refuses the boot over it.
 */
export type MfaTotpSettings =
	| (TotpFactorSettings & { readonly enabled: true })
	| (Omit<TotpFactorSettings, "issuer"> & {
			readonly enabled: false;
			readonly issuer: string | undefined;
	  });

/** What this package reads from the `mfa` section. */
export interface MfaSettings {
	/** The ring, in order: the first key seals, every key opens. */
	readonly encryptionKeys: SealingKeyRing;
	/**
	 * Whether the ring carries {@link MFA_DEVELOPMENT_SAMPLE_KEY} — accepted,
	 * since the settings refuse it outside development — so the MFA module can
	 * say so at boot.
	 */
	readonly developmentSampleKeyAccepted: boolean;
	readonly totp: MfaTotpSettings;
	/** A transaction's life, in seconds: every `expiresAtMs` is derived from it and nothing else (D8). */
	readonly transactionTtlSeconds: number;
	/** The attempts one transaction allows (D21). */
	readonly maxAttemptsPerTransaction: number;
	/** D21's subject lock, held to core's rule. */
	readonly lockout: MfaLockoutPolicy;
}

/** What a composition root tells the settings that its configuration cannot (#473). */
export interface MfaSettingsOptions {
	/**
	 * The name the deployment selected its configuration by — the standalone
	 * passes `CONFIG_ENV || NODE_ENV`. Read beside `NODE_ENV`, which is always
	 * consulted, by the sample-key refusal.
	 */
	readonly environment?: string;
}

const RING = "mfa.encryptionKeys";
const PRODUCTION_ENVIRONMENTS: ReadonlySet<string> = new Set(["production", "staging"]);

interface ConfigShape {
	readonly mfa?: unknown;
	readonly oauth?: { readonly jwt?: { readonly issuer?: unknown } };
	readonly deployment?: { readonly mode?: unknown };
}

/** `path` under `prefix`, an array index in brackets. */
const pathOf = (prefix: string, path: readonly PropertyKey[]): string =>
	path.reduce<string>(
		(text, segment) =>
			typeof segment === "number" ? `${text}[${segment}]` : `${text}.${String(segment)}`,
		prefix,
	);

/** `value` parsed by `schema`, or a `RangeError` naming each key refused, under `prefix`. */
function parseSection<T>(schema: z.ZodType<T>, value: unknown, prefix: string): T {
	const result = schema.safeParse(value);
	if (result.success) return result.data;
	throw new RangeError(
		result.error.issues.map((issue) => `${pathOf(prefix, issue.path)} ${issue.message}`).join("; "),
	);
}

/** The host `oauth.jwt.issuer` names, which the TOTP issuer defaults to. */
function issuerHost(config: ConfigShape): string {
	const issuer = config.oauth?.jwt?.issuer;
	let host = "";
	if (typeof issuer === "string") {
		try {
			host = new URL(issuer).hostname;
		} catch {
			host = "";
		}
	}
	// A bracketed IPv6 host would carry the colon the label cannot.
	if (host === "" || host.includes(":")) {
		throw new RangeError(
			"mfa.factors.totp.issuer is not set, and oauth.jwt.issuer names no host it could default to: set MFA_TOTP_ISSUER",
		);
	}
	return host;
}

function totpSettings(
	totp: z.infer<typeof mfaTotpConfigSchema>,
	config: ConfigShape,
): MfaTotpSettings {
	const parameters = {
		algorithm: totp.algorithm,
		digits: totp.digits,
		period: totp.period,
		window: totp.window,
	};
	return totp.enabled
		? { enabled: true, ...parameters, issuer: totp.issuer ?? issuerHost(config) }
		: { enabled: false, ...parameters, issuer: totp.issuer };
}

/** `mfa.factors.totp`, read on its own — what the TOTP factor's module reads. A `RangeError` names each key refused. */
export function readMfaTotpSettings(config: unknown): MfaTotpSettings {
	const shape = (config ?? {}) as ConfigShape;
	const section = parseSection(
		z.object({ factors: factorsSchema }, { error: SECTION_MISSING }),
		shape.mfa,
		"mfa",
	);
	return totpSettings(section.factors.totp, shape);
}

/**
 * The sample key's refusal (#473's rule): the environment the configuration
 * was selected by, or `NODE_ENV`, is production or staging, or
 * `deployment.mode` is `"multi"`. Every key opens, so it is refused wherever
 * it sits in the ring. Answers whether the ring carries it — accepted, when
 * this did not refuse it.
 */
function refuseSampleKey(
	ring: SealingKeyRing,
	config: ConfigShape,
	options: MfaSettingsOptions,
): boolean {
	const sample = decodeSealingKey(MFA_DEVELOPMENT_SAMPLE_KEY);
	const index = ring.findIndex((entry) => sample !== undefined && entry.key.equals(sample));
	if (index === -1) return false;
	// Both names are consulted, each whatever its case and the whitespace
	// around it — "Production" or "production\n" names production as surely —
	// and the one that matched is the one reported, normalised.
	const productionEnvironment = [options.environment, process.env.NODE_ENV]
		.map((name) => (typeof name === "string" ? name.trim().toLowerCase() : undefined))
		.find((name): name is string => name !== undefined && PRODUCTION_ENVIRONMENTS.has(name));
	const reasons: string[] = [];
	if (productionEnvironment !== undefined) {
		reasons.push(`the environment is "${productionEnvironment}"`);
	}
	if (config.deployment?.mode === "multi") {
		reasons.push(
			'deployment.mode is "multi" (a multi-replica deployment is never a development box)',
		);
	}
	if (reasons.length === 0) return true;
	throw new RangeError(
		`${RING}[${index}].key is the development sample key (MFA_DEVELOPMENT_SAMPLE_KEY), refused because ${reasons.join(" and ")}: set MFA_ENCRYPTION_KEY to a key of your own (openssl rand -base64 32)`,
	);
}

/** What an entry's fingerprint is derived under. */
const KEY_ID_LABEL = "o3co:mfa:key-id";

/**
 * The id of an entry written without one: `k` and the first 16 characters of
 * base64url(HMAC-SHA-256(key, `o3co:mfa:key-id`)). The same key is always
 * named the same and another key otherwise, so a key changed in place leaves
 * what the old one sealed `key_unavailable`, naming it, rather than
 * `unreadable` under an id both keys share. A PRF's output: it tells nothing
 * of the key, and may be logged.
 */
const keyFingerprint = (key: Buffer): string =>
	`k${createHmac("sha256", key).update(KEY_ID_LABEL).digest("base64url").slice(0, 16)}`;

/**
 * The ring the entries name, and whether it carries the development sample
 * key, or a `RangeError` naming the entry refused and quoting none.
 */
function readKeyRing(
	entries: z.infer<typeof mfaConfigSchema>["encryptionKeys"],
	config: ConfigShape,
	options: MfaSettingsOptions,
): { readonly ring: SealingKeyRing; readonly developmentSampleKeyAccepted: boolean } {
	if (entries.length === 0) {
		throw new RangeError(
			`${RING} is empty: set MFA_ENCRYPTION_KEY to a key of your own (openssl rand -base64 32)`,
		);
	}
	const ring = entries.map((entry, index) => {
		if (entry.key === undefined) {
			throw new RangeError(
				`${RING}[${index}].key is not set${index === 0 ? ": set MFA_ENCRYPTION_KEY, which feeds it (openssl rand -base64 32)" : ""}`,
			);
		}
		const key = decodeSealingKey(entry.key);
		if (key === undefined) {
			throw new RangeError(
				`${RING}[${index}].key must be canonical base64 of ${SEALING_KEY_BYTES} bytes`,
			);
		}
		return { id: entry.id ?? keyFingerprint(key), key };
	});
	checkSealingKeyRing(ring, RING);
	return { ring, developmentSampleKeyAccepted: refuseSampleKey(ring, config, options) };
}

/**
 * Everything this package reads from the `mfa` section: the key ring and
 * whether it carries the development sample key, the TOTP factor's settings,
 * a transaction's life and attempts, and the subject lock — held to core's
 * `checkMfaLockoutPolicy` under `mfa.lockout`. `options.environment` is the
 * name the composition root selected its configuration by (#473). A refusal
 * is a `RangeError` that names the key and quotes no key material.
 */
export function readMfaSettings(config: unknown, options: MfaSettingsOptions = {}): MfaSettings {
	const shape = (config ?? {}) as ConfigShape;
	const section = parseSection(mfaConfigSchema, shape.mfa, "mfa");
	const { ring, developmentSampleKeyAccepted } = readKeyRing(
		section.encryptionKeys,
		shape,
		options,
	);
	checkMfaLockoutPolicy(section.lockout, "mfa.lockout");
	return {
		encryptionKeys: ring,
		developmentSampleKeyAccepted,
		totp: totpSettings(section.factors.totp, shape),
		transactionTtlSeconds: section.transactionTtlSeconds,
		maxAttemptsPerTransaction: section.maxAttemptsPerTransaction,
		lockout: { ...section.lockout },
	};
}
