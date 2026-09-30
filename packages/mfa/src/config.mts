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
 * The configuration this package reads: the MFA module's own section, `mfa`,
 * and the TOTP factor's, `mfa-totp-factor`, each its module's alone. Keys,
 * ranges, defaults and refusals: see README, Configuration, and ADR
 * 2026-09-25-multi-factor-authentication.
 *
 * `mfa-totp-factor` is read by the TOTP factor's module alone
 * (`readMfaTotpSettings`), which never holds a key; the MFA module's settings
 * read no factor's section. The bounds on digits, period, a transaction's
 * life and its attempts are owner decisions, recorded in the ADR's
 * amendments rather than its decisions. A refusal is a `RangeError` whose
 * message starts with the key and quotes no key or id.
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
 * configuration may carry in place of `MFA_ENCRYPTION_KEY`. Everyone
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

/**
 * {@link wholeNumber}, or the decimal digits an environment variable carries
 * as a string, which every leaf of a module's section must read. Nothing
 * else is read as a number: not `null`, `true`, `""`, `"0x10"` or `"1e1"`,
 * which `z.coerce.number()` would turn into one.
 */
const environmentWholeNumber = (min: number, max: number, unit: string) => {
	const error = `must be a whole number from ${min} to ${max}${unit}`;
	const bounded = wholeNumber(min, max, unit);
	return z.union(
		[bounded, z.string({ error }).trim().regex(/^\d+$/, { error }).transform(Number).pipe(bounded)],
		{ error },
	);
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

/**
 * The TOTP factor's section, `mfa-totp-factor`: its switch and parameters,
 * and the issuer an authenticator app shows. The TOTP factor's module parses
 * it with this schema before any factory runs; the issuer's default, which
 * needs the deployment's issuer, is `readMfaTotpSettings`'s.
 */
export const mfaTotpConfigSchema = z.object(
	{
		enabled: coerceBooleanFromEnv,
		algorithm: z.enum(TOTP_ALGORITHMS, {
			error: `must be one of ${TOTP_ALGORITHMS.map((name) => `"${name}"`).join(", ")}`,
		}),
		digits: environmentWholeNumber(6, 8, ""),
		period: environmentWholeNumber(15, 120, " seconds"),
		window: environmentWholeNumber(0, 2, " steps"),
		issuer: z
			.string({ error: ISSUER_RULE })
			.refine(isShowableIssuer, { error: ISSUER_RULE })
			.optional(),
	},
	{ error: SECTION_MISSING },
);

/**
 * `mfa.mode`: whether a password login asks for a second factor. `required`:
 * every password login has one and every consumer enforces it. `optional`:
 * users with factors are challenged, nobody is forced, step-up works. `off`:
 * the MFA module refuses it — installed is on.
 */
export const MFA_MODES = ["off", "optional", "required"] as const;

/** `mfa.mode`, one of {@link MFA_MODES}; anything else is refused, never read as `off`. */
const mfaModeSchema = z.enum(MFA_MODES, { error: 'must be "off", "optional" or "required"' });

const RING_SHAPE = "must be a list of { id?, key } entries";

/** The fewest and the most attempts one transaction may allow. */
const MFA_MAX_ATTEMPTS_PER_TRANSACTION = { min: 1, max: 10 } as const;

const POSITIVE_WHOLE = "must be a positive whole number";
const positiveWhole = z
	.number({ error: POSITIVE_WHOLE })
	.int({ error: POSITIVE_WHOLE })
	.positive({ error: POSITIVE_WHOLE });

/**
 * `mfa.lockout`, the subject lock: each field a positive whole number here;
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
 * The MFA module's section, `mfa`: its mode, the key ring, a transaction's
 * life and attempts, and the subject lock, with the transaction's ranges. The
 * ring's refusals (a key that is not 32 bytes, an empty ring, a duplicate
 * id), the sample key's and how the lock's fields relate are not the
 * schema's: `readMfaSettings` makes them, where the keys are decoded, the
 * environment is known and core's rule is applied.
 */
export const mfaConfigSchema = z.object(
	{
		mode: mfaModeSchema,
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
		transactionTtlSeconds: wholeNumber(
			MFA_TRANSACTION_TTL_SECONDS.min,
			MFA_TRANSACTION_TTL_SECONDS.max,
			" seconds",
		),
		maxAttemptsPerTransaction: wholeNumber(
			MFA_MAX_ATTEMPTS_PER_TRANSACTION.min,
			MFA_MAX_ATTEMPTS_PER_TRANSACTION.max,
			"",
		),
		lockout: lockoutSchema,
	},
	{ error: SECTION_MISSING },
);

/**
 * What the MFA module's section schema checks before any factory runs: the
 * mode, which may be unset — the module refuses that as it refuses `off` —
 * and every other key handed on unread, for {@link readMfaSettings}. The
 * section may be missing: its settings are then refused, naming the
 * `reference.conf` that carries them.
 */
export const mfaSectionSchema = mfaConfigSchema.pick({ mode: true }).partial().loose().optional();

/** What the MFA module's settings parse: every key of {@link mfaConfigSchema} but the mode. */
const mfaModuleSettingsSchema = mfaConfigSchema.omit({ mode: true });

/**
 * `mfa-totp-factor` as the factor and its module read it: the switch and the
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

/** What the MFA module reads from its `mfa` section, but the mode. */
export interface MfaSettings {
	/** The ring, in order: the first key seals, every key opens. */
	readonly encryptionKeys: SealingKeyRing;
	/**
	 * Whether the ring carries {@link MFA_DEVELOPMENT_SAMPLE_KEY} — accepted,
	 * since the settings refuse it outside development — so the MFA module can
	 * say so at boot.
	 */
	readonly developmentSampleKeyAccepted: boolean;
	/** A transaction's life, in seconds: every `expiresAtMs` is derived from it and nothing else. */
	readonly transactionTtlSeconds: number;
	/** The attempts one transaction allows. */
	readonly maxAttemptsPerTransaction: number;
	/** The subject lock, held to core's rule. */
	readonly lockout: MfaLockoutPolicy;
}

/** What the settings read beside the `mfa` section. */
export interface MfaSettingsOptions {
	/**
	 * The name the deployment selected its configuration by — the standalone
	 * passes `CONFIG_ENV || NODE_ENV`. Read beside `NODE_ENV`, which is always
	 * consulted, by the sample-key refusal.
	 */
	readonly environment?: string;
	/**
	 * `deployment.mode` as the configuration carries it — the MFA module
	 * passes it: `"multi"` refuses the sample key.
	 */
	readonly deploymentMode?: unknown;
}

/** The TOTP factor's section: what its refusals name. */
const TOTP_SECTION = "mfa-totp-factor";

const RING = "mfa.encryptionKeys";
const PRODUCTION_ENVIRONMENTS: ReadonlySet<string> = new Set(["production", "staging"]);

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

/**
 * The host of `issuer`, the deployment's issuer, which the TOTP issuer
 * defaults to.
 */
function issuerHost(issuer: unknown): string {
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
			`${TOTP_SECTION}.issuer is not set, and oauth.jwt.issuer names no host it could default to: set MFA_TOTP_FACTOR_ISSUER`,
		);
	}
	return host;
}

function totpSettings(totp: z.infer<typeof mfaTotpConfigSchema>, issuer: unknown): MfaTotpSettings {
	const parameters = {
		algorithm: totp.algorithm,
		digits: totp.digits,
		period: totp.period,
		window: totp.window,
	};
	return totp.enabled
		? { enabled: true, ...parameters, issuer: totp.issuer ?? issuerHost(issuer) }
		: { enabled: false, ...parameters, issuer: totp.issuer };
}

/**
 * The TOTP factor's section, `mfa-totp-factor` — what the TOTP factor's
 * module reads. A `RangeError` names each key refused. `options.issuer` is
 * the deployment's issuer — the `oauthTokenSettings` slot's when the
 * composition holds it, `oauth.jwt.issuer` otherwise — whose host an unset
 * TOTP issuer defaults to.
 */
export function readMfaTotpSettings(
	section: unknown,
	options: { readonly issuer?: unknown } = {},
): MfaTotpSettings {
	return totpSettings(parseSection(mfaTotpConfigSchema, section, TOTP_SECTION), options.issuer);
}

/**
 * The sample key's refusal: the environment the configuration
 * was selected by, or `NODE_ENV`, is production or staging, or
 * `deployment.mode` is `"multi"`. Every key opens, so it is refused wherever
 * it sits in the ring. Answers whether the ring carries it — accepted, when
 * this did not refuse it.
 */
function refuseSampleKey(ring: SealingKeyRing, options: MfaSettingsOptions): boolean {
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
	if (options.deploymentMode === "multi") {
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
	refuseRepeatedKey(ring);
	return { ring, developmentSampleKeyAccepted: refuseSampleKey(ring, options) };
}

/**
 * One key under two ids — `{ id: "old", key: X }` beside `{ id: "new", key:
 * X }` — is one AES key posing as two rotation generations: retiring one
 * would retire nothing. Core's ring rule compares ids alone, so the decoded
 * keys are compared here, and the later entry is refused, named by its index
 * and the earlier one's, quoting neither key nor id. Boot-time, over a
 * handful of entries: no comparison needs to be constant-time.
 */
function refuseRepeatedKey(ring: SealingKeyRing): void {
	ring.forEach((entry, index) => {
		const earlier = ring.findIndex((other) => other.key.equals(entry.key));
		if (earlier < index) {
			throw new RangeError(
				`${RING}[${index}].key duplicates the key of ${RING}[${earlier}] under another id: one key cannot be two rotation generations — give each entry a key of its own (openssl rand -base64 32)`,
			);
		}
	});
}

/**
 * What the MFA module reads from its `mfa` section, `section`: the key ring
 * and whether it carries the development sample key, a transaction's life
 * and attempts, and the subject lock — held to core's
 * `checkMfaLockoutPolicy` under `mfa.lockout`. Not the mode, which the
 * module's section schema reads, and no factor's section: the TOTP factor's
 * is {@link readMfaTotpSettings}'s. `options.environment` is the name the
 * composition root selected its configuration by. A refusal is a
 * `RangeError` that names the key and quotes no key material.
 */
export function readMfaSettings(section: unknown, options: MfaSettingsOptions = {}): MfaSettings {
	const settings = parseSection(mfaModuleSettingsSchema, section, "mfa");
	const { ring, developmentSampleKeyAccepted } = readKeyRing(settings.encryptionKeys, options);
	checkMfaLockoutPolicy(settings.lockout, "mfa.lockout");
	return {
		encryptionKeys: ring,
		developmentSampleKeyAccepted,
		transactionTtlSeconds: settings.transactionTtlSeconds,
		maxAttemptsPerTransaction: settings.maxAttemptsPerTransaction,
		lockout: { ...settings.lockout },
	};
}
