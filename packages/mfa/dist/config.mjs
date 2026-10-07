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
 * and the TOTP factor's, `mfa-totp-factor`, each its module's alone (the
 * recovery-code factor's section is read beside its module, in `recovery/`,
 * with the readers shared from here). Keys,
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
import { checkConfiguredMfaLockoutPolicy, checkDeploymentMode, checkSealingKeyRing, coerceBooleanFromEnv, decodeSealingKey, hasControlCharacter, isDevelopmentEnvironment, MFA_RECOVERY_AUTHORIZATION_MAX_MS, productionEnvironmentIn, readEnvironmentName, SEALING_KEY_BYTES, } from "@o3co/auth-provider-core";
import { z } from "zod";
import { checkFactorSetStoreTimeout } from "./factorSet.mjs";
import { REQUIRE_EMAIL_PROOF } from "./firstBinding.mjs";
import { TOTP_ALGORITHMS } from "./totp/rfc6238.mjs";
import { MFA_TRANSACTION_TTL_SECONDS } from "./transactions.mjs";
/**
 * A published key for development only — canonical base64 of 32 bytes, the
 * ASCII text `o3co:mfa:development-sample-key!` — which a development
 * configuration may carry in place of `MFA_ENCRYPTION_KEY`. Everyone
 * holds it, so data sealed under it is sealed from nobody: the settings
 * accept it only where the name the configuration was selected by and
 * `NODE_ENV`, each where set, say development or test, with at least one
 * set, and refuse it under the deployment mode `"multi"`.
 */
export const MFA_DEVELOPMENT_SAMPLE_KEY = "bzNjbzptZmE6ZGV2ZWxvcG1lbnQtc2FtcGxlLWtleSE=";
const SECTION_MISSING = "is missing: layer @o3co/auth-provider-mfa/reference.conf beneath the composition's configuration";
/** The keys an unknown-key issue names, each as written, or quoted when it is not a plain identifier. */
const unknownKeys = (keys) => (keys ?? [])
    .map((key) => typeof key === "string" && /^[A-Za-z0-9_-]+$/.test(key) ? key : JSON.stringify(key))
    .join(", ");
/**
 * A section's refusal: missing, written as a value rather than a section of
 * keys, or holding a key the section does not know, named.
 */
export const sectionError = (issue) => issue.code === "unrecognized_keys"
    ? `has a key it does not know: ${unknownKeys(issue.keys)}`
    : issue.input === undefined
        ? SECTION_MISSING
        : "must be a section of keys";
const wholeNumber = (min, max, unit) => {
    const error = `must be a whole number from ${min} to ${max}${unit}`;
    return z.number({ error }).int({ error }).min(min, { error }).max(max, { error });
};
/**
 * `bounded`, or the decimal digits an environment variable carries as a
 * string, whitespace around them allowed, read as their number and held to
 * `bounded` — what every leaf of a module's section must read. Nothing else
 * is read as a number: not `null`, `true`, `""`, `"0x10"` or `"1e1"`, which
 * `z.coerce.number()` would turn into one.
 */
const fromEnvironment = (bounded, error) => z.union([bounded, z.string({ error }).trim().regex(/^\d+$/, { error }).transform(Number).pipe(bounded)], { error });
/** A whole number from `min` to `max`, as {@link fromEnvironment} reads one. */
export const environmentWholeNumber = (min, max, unit) => fromEnvironment(wholeNumber(min, max, unit), `must be a whole number from ${min} to ${max}${unit}`);
const ISSUER_RULE = "must be well-formed text, not blank, with no control character and no colon — the otpauth label puts one between the issuer and the account";
/** An issuer the otpauth label can carry, and an authenticator app can show. */
const isShowableIssuer = (issuer) => issuer.isWellFormed() &&
    issuer.trim() !== "" &&
    !hasControlCharacter(issuer) &&
    !issuer.includes(":");
/**
 * The TOTP factor's section, `mfa-totp-factor`: its switch and parameters,
 * and the issuer an authenticator app shows. Strict: a key the section does
 * not know is refused by its name. The TOTP factor's module parses it with
 * this schema before any factory runs; the issuer's default, which needs the
 * deployment's issuer, is `readMfaTotpSettings`'s.
 */
export const mfaTotpConfigSchema = z.strictObject({
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
}, { error: sectionError });
/**
 * `mfa.mode`: whether a password login asks for a second factor. `required`:
 * every password login has one and every consumer enforces it. `optional`:
 * users with factors are challenged, nobody is forced, step-up works. `off`:
 * the MFA module refuses it — installed is on.
 */
export const MFA_MODES = ["off", "optional", "required"];
/** `mfa.mode`, one of {@link MFA_MODES}; anything else is refused, never read as `off`. */
const mfaModeSchema = z.enum(MFA_MODES, { error: 'must be "off", "optional" or "required"' });
const RING_SHAPE = "must be a list of { id?, key } entries";
/** An entry of the ring's refusal: a key it does not know, named, or {@link RING_SHAPE}. */
const ringEntryError = (issue) => issue.code === "unrecognized_keys" ? sectionError(issue) : RING_SHAPE;
/**
 * The fewest and the most attempts one transaction may allow: an email-proof
 * first binding spends one on the proof and one on the binding.
 */
const MFA_MAX_ATTEMPTS_PER_TRANSACTION = { min: 2, max: 10 };
const POSITIVE_WHOLE = "must be a positive whole number";
const positiveWhole = fromEnvironment(z
    .number({ error: POSITIVE_WHOLE })
    .int({ error: POSITIVE_WHOLE })
    .positive({ error: POSITIVE_WHOLE }), POSITIVE_WHOLE);
/**
 * `mfa.lockout`, the subject lock: each field a positive whole number here;
 * how the fields relate — `hardLimit` at least 10, above `threshold` and at
 * most NIST's cap, `maxSeconds` at least `baseSeconds`, every duration within
 * the Date range — is core's `checkConfiguredMfaLockoutPolicy`, which
 * `readMfaSettings` applies under the key.
 */
const lockoutSchema = z.strictObject({
    threshold: positiveWhole,
    baseSeconds: positiveWhole,
    maxSeconds: positiveWhole,
    memorySeconds: positiveWhole,
    weeklyBudget: positiveWhole,
    hardLimit: positiveWhole,
}, { error: sectionError });
/** `mfa.page`, the MFA page a step-up starts on: a section holding its `url`. */
const mfaPageSchema = z.strictObject({ url: z.string({ error: "must be a string" }) }, { error: sectionError });
/**
 * The least and the most time a second factor verified in a session stays
 * recent, in seconds. The most is core's `MFA_RECOVERY_AUTHORIZATION_MAX_MS`:
 * an authorized recovery minted at an exempt verification lasts this long
 * (`lockRecovery.mts`), and the store refuses one that lasts longer.
 */
export const MFA_RECENT_WINDOW_SECONDS = {
    min: 60,
    max: MFA_RECOVERY_AUTHORIZATION_MAX_MS / 1000,
};
/**
 * `mfa.manage`: `maxAgeSeconds`, how long a second factor verified in a
 * session stays recent — what adding or removing a way into the account asks
 * of the session.
 */
const manageSchema = z.strictObject({
    maxAgeSeconds: environmentWholeNumber(MFA_RECENT_WINDOW_SECONDS.min, MFA_RECENT_WINDOW_SECONDS.max, " seconds"),
}, { error: sectionError });
/**
 * The fewest and the most records a subject may hold: a first binding writes
 * a factor and its recovery codes.
 */
const MFA_MAX_FACTORS_PER_SUBJECT = { min: 2, max: 100 };
/**
 * `mfa.enrollment`: `requireEmailProof`, whether the account-email proof
 * comes before a first binding (the MFA ADR's D24) — `when-mail`, `always`
 * or `never`.
 */
const enrollmentSchema = z.strictObject({
    requireEmailProof: z.enum(REQUIRE_EMAIL_PROOF, {
        error: 'must be "when-mail", "always" or "never"',
    }),
}, { error: sectionError });
/** `mfa.storeTimeoutMs`'s range: from 1000 ms; the most a lease allows is `factorSet.mts`'s to refuse. */
const MFA_STORE_TIMEOUT_MS = { min: 1_000, max: 2_147_483_647 };
/**
 * The MFA module's section, `mfa`: its mode, the page's shape, the key ring,
 * a transaction's life and attempts, the subject lock, recent MFA's window,
 * the first binding's proof and the records a subject may hold, with their
 * ranges. Strict at every level: a key the section does
 * not know is refused by its name. Every number also reads the decimal digits
 * an environment variable carries. The page may be left out, and an empty url
 * is allowed: the module refuses either as unset. The ring's refusals (a key
 * that is not 32 bytes, an empty ring, a duplicate id), the sample key's and
 * how the lock's fields relate are not the schema's: `readMfaSettings` and the
 * module make them, where the keys are decoded, the environment is known and
 * core's rules are applied.
 */
export const mfaConfigSchema = z.strictObject({
    mode: mfaModeSchema,
    page: mfaPageSchema.optional(),
    encryptionKeys: z.array(z.strictObject({
        id: z.string({ error: "must be a string, or left out" }).optional(),
        key: z.string({ error: "must be canonical base64 of 32 bytes" }).optional(),
    }, { error: ringEntryError }), { error: RING_SHAPE }),
    transactionTtlSeconds: environmentWholeNumber(MFA_TRANSACTION_TTL_SECONDS.min, MFA_TRANSACTION_TTL_SECONDS.max, " seconds"),
    maxAttemptsPerTransaction: environmentWholeNumber(MFA_MAX_ATTEMPTS_PER_TRANSACTION.min, MFA_MAX_ATTEMPTS_PER_TRANSACTION.max, ""),
    lockout: lockoutSchema,
    manage: manageSchema,
    enrollment: enrollmentSchema,
    maxFactorsPerSubject: environmentWholeNumber(MFA_MAX_FACTORS_PER_SUBJECT.min, MFA_MAX_FACTORS_PER_SUBJECT.max, " records"),
    storeTimeoutMs: environmentWholeNumber(MFA_STORE_TIMEOUT_MS.min, MFA_STORE_TIMEOUT_MS.max, " milliseconds"),
}, { error: sectionError });
/** The `mfa` section as the MFA module reads it: {@link mfaConfigSchema}, its mode left out reading as unset. */
const mfaSectionObjectSchema = mfaConfigSchema.partial({ mode: true });
/**
 * What the MFA module's section schema checks before any factory runs: the
 * whole section, as {@link mfaConfigSchema} holds it, every key it does not
 * know refused. A missing section or mode reads as unset, which the module
 * refuses as it refuses `off`; a missing page or an empty url is the module's
 * to refuse, and so is what {@link readMfaSettings} refuses beyond the schema.
 */
export const mfaSectionSchema = mfaSectionObjectSchema.optional();
/** The TOTP factor's section: what its refusals name. */
const TOTP_SECTION = "mfa-totp-factor";
const RING = "mfa.encryptionKeys";
/** `path` under `prefix`, an array index in brackets. */
const pathOf = (prefix, path) => path.reduce((text, segment) => typeof segment === "number" ? `${text}[${segment}]` : `${text}.${String(segment)}`, prefix);
/** `value` parsed by `schema`, or a `RangeError` naming each key refused, under `prefix`. */
function parseSection(schema, value, prefix) {
    const result = schema.safeParse(value);
    if (result.success)
        return result.data;
    throw new RangeError(result.error.issues.map((issue) => `${pathOf(prefix, issue.path)} ${issue.message}`).join("; "));
}
/**
 * The host of `issuer`, the deployment's issuer, which the TOTP issuer
 * defaults to.
 */
function issuerHost(issuer) {
    let host = "";
    if (typeof issuer === "string") {
        try {
            host = new URL(issuer).hostname;
        }
        catch {
            host = "";
        }
    }
    // A bracketed IPv6 host would carry the colon the label cannot.
    if (host === "" || host.includes(":")) {
        throw new RangeError(`${TOTP_SECTION}.issuer is not set, and the deployment's issuer (the oauthTokenSettings slot's) names no host it could default to: set MFA_TOTP_FACTOR_ISSUER`);
    }
    return host;
}
function totpSettings(totp, issuer) {
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
 * the deployment's issuer — the `oauthTokenSettings` slot's — whose host an
 * unset TOTP issuer defaults to.
 */
export function readMfaTotpSettings(section, options = {}) {
    return totpSettings(parseSection(mfaTotpConfigSchema, section, TOTP_SECTION), options.issuer);
}
/**
 * The sample key's refusal: unless the environment the configuration was
 * selected by and `NODE_ENV`, each where set, say development or test, with
 * at least one set; and under `options.deploymentMode` `"multi"`. Every key
 * opens, so it is refused wherever it sits in the ring. Answers whether the
 * ring carries it — accepted, when this did not refuse it.
 */
function refuseSampleKey(ring, options) {
    const sample = decodeSealingKey(MFA_DEVELOPMENT_SAMPLE_KEY);
    const index = ring.findIndex((entry) => sample !== undefined && entry.key.equals(sample));
    if (index === -1)
        return false;
    const reasons = environmentRefusals([options.environment, process.env.NODE_ENV]);
    if (options.deploymentMode === "multi") {
        reasons.push('core.deployment.mode is "multi" (a multi-replica deployment is never a development box)');
    }
    if (reasons.length === 0)
        return true;
    throw new RangeError(`${RING}[${index}].key is the development sample key (MFA_DEVELOPMENT_SAMPLE_KEY), refused because ${reasons.join(" and ")}: set MFA_ENCRYPTION_KEY to a key of your own (openssl rand -base64 32)`);
}
/**
 * Why `names` do not let the sample key in, as core reads them: each name set
 * that says production or staging, or else neither development nor test, as
 * read; or that none is set.
 */
function environmentRefusals(names) {
    if (isDevelopmentEnvironment(names))
        return [];
    const read = [...new Set(names.map(readEnvironmentName).filter((name) => name !== undefined))];
    if (read.length === 0)
        return ["no environment is named"];
    return read
        .filter((name) => !isDevelopmentEnvironment([name]))
        .map((name) => productionEnvironmentIn([name]) === undefined
        ? `the environment "${name}" is not development or test`
        : `the environment is "${name}"`);
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
const keyFingerprint = (key) => `k${createHmac("sha256", key).update(KEY_ID_LABEL).digest("base64url").slice(0, 16)}`;
/**
 * The ring the entries name, and whether it carries the development sample
 * key, or a `RangeError` naming the entry refused and quoting none.
 */
function readKeyRing(entries, options) {
    if (entries.length === 0) {
        throw new RangeError(`${RING} is empty: set MFA_ENCRYPTION_KEY to a key of your own (openssl rand -base64 32)`);
    }
    const ring = entries.map((entry, index) => {
        if (entry.key === undefined) {
            throw new RangeError(`${RING}[${index}].key is not set${index === 0 ? ": set MFA_ENCRYPTION_KEY, which feeds it (openssl rand -base64 32)" : ""}`);
        }
        const key = decodeSealingKey(entry.key);
        if (key === undefined) {
            throw new RangeError(`${RING}[${index}].key must be canonical base64 of ${SEALING_KEY_BYTES} bytes`);
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
function refuseRepeatedKey(ring) {
    ring.forEach((entry, index) => {
        const earlier = ring.findIndex((other) => other.key.equals(entry.key));
        if (earlier < index) {
            throw new RangeError(`${RING}[${index}].key duplicates the key of ${RING}[${earlier}] under another id: one key cannot be two rotation generations — give each entry a key of its own (openssl rand -base64 32)`);
        }
    });
}
/**
 * What the MFA module reads from its `mfa` section, `section`: the key ring
 * and whether it carries the development sample key, a transaction's life
 * and attempts, recent MFA's window, the first binding's proof, the records
 * a subject may hold, and the subject lock — held to core's
 * `checkConfiguredMfaLockoutPolicy` under `mfa.lockout`. The whole section is
 * held to its schema, as the module's section schema holds it; not the mode
 * or the page, which the module reads from its section, and no factor's
 * section: the TOTP factor's is {@link readMfaTotpSettings}'s. `options.environment` is the name the
 * composition root selected its configuration by, and
 * `options.deploymentMode` the `deploymentMode` slot's value. A refusal is a
 * `RangeError` that names the key and quotes no key material.
 */
export function readMfaSettings(section, options) {
    checkDeploymentMode(options.deploymentMode, "mfa settings: deploymentMode");
    const settings = parseSection(mfaSectionObjectSchema, section, "mfa");
    const { ring, developmentSampleKeyAccepted } = readKeyRing(settings.encryptionKeys, options);
    checkConfiguredMfaLockoutPolicy(settings.lockout, "mfa.lockout");
    return {
        encryptionKeys: ring,
        developmentSampleKeyAccepted,
        transactionTtlSeconds: settings.transactionTtlSeconds,
        maxAttemptsPerTransaction: settings.maxAttemptsPerTransaction,
        lockout: { ...settings.lockout },
        manage: { maxAgeSeconds: settings.manage.maxAgeSeconds },
        enrollment: { requireEmailProof: settings.enrollment.requireEmailProof },
        maxFactorsPerSubject: settings.maxFactorsPerSubject,
        storeTimeoutMs: checkFactorSetStoreTimeout(settings.storeTimeoutMs),
    };
}
