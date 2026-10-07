import { type DeploymentMode, type MfaLockoutPolicy, type SealingKeyRing } from "@o3co/auth-provider-core";
import { z } from "zod";
import { type RequireEmailProof } from "./firstBinding.mjs";
import type { TotpFactorSettings } from "./totp/factor.mjs";
/**
 * A published key for development only — canonical base64 of 32 bytes, the
 * ASCII text `o3co:mfa:development-sample-key!` — which a development
 * configuration may carry in place of `MFA_ENCRYPTION_KEY`. Everyone
 * holds it, so data sealed under it is sealed from nobody: the settings
 * accept it only where the name the configuration was selected by and
 * `NODE_ENV`, each where set, say development or test, with at least one
 * set, and refuse it under the deployment mode `"multi"`.
 */
export declare const MFA_DEVELOPMENT_SAMPLE_KEY = "bzNjbzptZmE6ZGV2ZWxvcG1lbnQtc2FtcGxlLWtleSE=";
/**
 * A section's refusal: missing, written as a value rather than a section of
 * keys, or holding a key the section does not know, named.
 */
export declare const sectionError: (issue: {
    readonly code?: string;
    readonly input?: unknown;
    readonly keys?: readonly unknown[];
}) => string;
/** A whole number from `min` to `max`, as {@link fromEnvironment} reads one. */
export declare const environmentWholeNumber: (min: number, max: number, unit: string) => z.ZodUnion<readonly [z.ZodNumber, z.ZodPipe<z.ZodPipe<z.ZodString, z.ZodTransform<number, string>>, z.ZodNumber>]>;
/**
 * The TOTP factor's section, `mfa-totp-factor`: its switch and parameters,
 * and the issuer an authenticator app shows. Strict: a key the section does
 * not know is refused by its name. The TOTP factor's module parses it with
 * this schema before any factory runs; the issuer's default, which needs the
 * deployment's issuer, is `readMfaTotpSettings`'s.
 */
export declare const mfaTotpConfigSchema: z.ZodObject<{
    enabled: z.ZodPreprocess<z.ZodBoolean, unknown>;
    algorithm: z.ZodEnum<{
        SHA1: "SHA1";
        SHA256: "SHA256";
        SHA512: "SHA512";
    }>;
    digits: z.ZodUnion<readonly [z.ZodNumber, z.ZodPipe<z.ZodPipe<z.ZodString, z.ZodTransform<number, string>>, z.ZodNumber>]>;
    period: z.ZodUnion<readonly [z.ZodNumber, z.ZodPipe<z.ZodPipe<z.ZodString, z.ZodTransform<number, string>>, z.ZodNumber>]>;
    window: z.ZodUnion<readonly [z.ZodNumber, z.ZodPipe<z.ZodPipe<z.ZodString, z.ZodTransform<number, string>>, z.ZodNumber>]>;
    issuer: z.ZodOptional<z.ZodString>;
}, z.core.$strict>;
/**
 * `mfa.mode`: whether a password login asks for a second factor. `required`:
 * every password login has one and every consumer enforces it. `optional`:
 * users with factors are challenged, nobody is forced, step-up works. `off`:
 * the MFA module refuses it — installed is on.
 */
export declare const MFA_MODES: readonly ["off", "optional", "required"];
/** `mfa.mode`, one of {@link MFA_MODES}. */
export type MfaMode = (typeof MFA_MODES)[number];
/**
 * The least and the most time a second factor verified in a session stays
 * recent, in seconds. The most is core's `MFA_RECOVERY_AUTHORIZATION_MAX_MS`:
 * an authorized recovery minted at an exempt verification lasts this long
 * (`lockRecovery.mts`), and the store refuses one that lasts longer.
 */
export declare const MFA_RECENT_WINDOW_SECONDS: {
    readonly min: 60;
    readonly max: number;
};
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
export declare const mfaConfigSchema: z.ZodObject<{
    mode: z.ZodEnum<{
        required: "required";
        optional: "optional";
        off: "off";
    }>;
    page: z.ZodOptional<z.ZodObject<{
        url: z.ZodString;
    }, z.core.$strict>>;
    encryptionKeys: z.ZodArray<z.ZodObject<{
        id: z.ZodOptional<z.ZodString>;
        key: z.ZodOptional<z.ZodString>;
    }, z.core.$strict>>;
    transactionTtlSeconds: z.ZodUnion<readonly [z.ZodNumber, z.ZodPipe<z.ZodPipe<z.ZodString, z.ZodTransform<number, string>>, z.ZodNumber>]>;
    maxAttemptsPerTransaction: z.ZodUnion<readonly [z.ZodNumber, z.ZodPipe<z.ZodPipe<z.ZodString, z.ZodTransform<number, string>>, z.ZodNumber>]>;
    lockout: z.ZodObject<{
        threshold: z.ZodUnion<readonly [z.ZodNumber, z.ZodPipe<z.ZodPipe<z.ZodString, z.ZodTransform<number, string>>, z.ZodNumber>]>;
        baseSeconds: z.ZodUnion<readonly [z.ZodNumber, z.ZodPipe<z.ZodPipe<z.ZodString, z.ZodTransform<number, string>>, z.ZodNumber>]>;
        maxSeconds: z.ZodUnion<readonly [z.ZodNumber, z.ZodPipe<z.ZodPipe<z.ZodString, z.ZodTransform<number, string>>, z.ZodNumber>]>;
        memorySeconds: z.ZodUnion<readonly [z.ZodNumber, z.ZodPipe<z.ZodPipe<z.ZodString, z.ZodTransform<number, string>>, z.ZodNumber>]>;
        weeklyBudget: z.ZodUnion<readonly [z.ZodNumber, z.ZodPipe<z.ZodPipe<z.ZodString, z.ZodTransform<number, string>>, z.ZodNumber>]>;
        hardLimit: z.ZodUnion<readonly [z.ZodNumber, z.ZodPipe<z.ZodPipe<z.ZodString, z.ZodTransform<number, string>>, z.ZodNumber>]>;
    }, z.core.$strict>;
    manage: z.ZodObject<{
        maxAgeSeconds: z.ZodUnion<readonly [z.ZodNumber, z.ZodPipe<z.ZodPipe<z.ZodString, z.ZodTransform<number, string>>, z.ZodNumber>]>;
    }, z.core.$strict>;
    enrollment: z.ZodObject<{
        requireEmailProof: z.ZodEnum<{
            "when-mail": "when-mail";
            always: "always";
            never: "never";
        }>;
    }, z.core.$strict>;
    maxFactorsPerSubject: z.ZodUnion<readonly [z.ZodNumber, z.ZodPipe<z.ZodPipe<z.ZodString, z.ZodTransform<number, string>>, z.ZodNumber>]>;
    storeTimeoutMs: z.ZodUnion<readonly [z.ZodNumber, z.ZodPipe<z.ZodPipe<z.ZodString, z.ZodTransform<number, string>>, z.ZodNumber>]>;
}, z.core.$strict>;
/**
 * What the MFA module's section schema checks before any factory runs: the
 * whole section, as {@link mfaConfigSchema} holds it, every key it does not
 * know refused. A missing section or mode reads as unset, which the module
 * refuses as it refuses `off`; a missing page or an empty url is the module's
 * to refuse, and so is what {@link readMfaSettings} refuses beyond the schema.
 */
export declare const mfaSectionSchema: z.ZodOptional<z.ZodObject<{
    mode: z.ZodOptional<z.ZodEnum<{
        required: "required";
        optional: "optional";
        off: "off";
    }>>;
    page: z.ZodOptional<z.ZodObject<{
        url: z.ZodString;
    }, z.core.$strict>>;
    encryptionKeys: z.ZodArray<z.ZodObject<{
        id: z.ZodOptional<z.ZodString>;
        key: z.ZodOptional<z.ZodString>;
    }, z.core.$strict>>;
    transactionTtlSeconds: z.ZodUnion<readonly [z.ZodNumber, z.ZodPipe<z.ZodPipe<z.ZodString, z.ZodTransform<number, string>>, z.ZodNumber>]>;
    maxAttemptsPerTransaction: z.ZodUnion<readonly [z.ZodNumber, z.ZodPipe<z.ZodPipe<z.ZodString, z.ZodTransform<number, string>>, z.ZodNumber>]>;
    lockout: z.ZodObject<{
        threshold: z.ZodUnion<readonly [z.ZodNumber, z.ZodPipe<z.ZodPipe<z.ZodString, z.ZodTransform<number, string>>, z.ZodNumber>]>;
        baseSeconds: z.ZodUnion<readonly [z.ZodNumber, z.ZodPipe<z.ZodPipe<z.ZodString, z.ZodTransform<number, string>>, z.ZodNumber>]>;
        maxSeconds: z.ZodUnion<readonly [z.ZodNumber, z.ZodPipe<z.ZodPipe<z.ZodString, z.ZodTransform<number, string>>, z.ZodNumber>]>;
        memorySeconds: z.ZodUnion<readonly [z.ZodNumber, z.ZodPipe<z.ZodPipe<z.ZodString, z.ZodTransform<number, string>>, z.ZodNumber>]>;
        weeklyBudget: z.ZodUnion<readonly [z.ZodNumber, z.ZodPipe<z.ZodPipe<z.ZodString, z.ZodTransform<number, string>>, z.ZodNumber>]>;
        hardLimit: z.ZodUnion<readonly [z.ZodNumber, z.ZodPipe<z.ZodPipe<z.ZodString, z.ZodTransform<number, string>>, z.ZodNumber>]>;
    }, z.core.$strict>;
    manage: z.ZodObject<{
        maxAgeSeconds: z.ZodUnion<readonly [z.ZodNumber, z.ZodPipe<z.ZodPipe<z.ZodString, z.ZodTransform<number, string>>, z.ZodNumber>]>;
    }, z.core.$strict>;
    enrollment: z.ZodObject<{
        requireEmailProof: z.ZodEnum<{
            "when-mail": "when-mail";
            always: "always";
            never: "never";
        }>;
    }, z.core.$strict>;
    maxFactorsPerSubject: z.ZodUnion<readonly [z.ZodNumber, z.ZodPipe<z.ZodPipe<z.ZodString, z.ZodTransform<number, string>>, z.ZodNumber>]>;
    storeTimeoutMs: z.ZodUnion<readonly [z.ZodNumber, z.ZodPipe<z.ZodPipe<z.ZodString, z.ZodTransform<number, string>>, z.ZodNumber>]>;
}, z.core.$strict>>;
/**
 * `mfa-totp-factor` as the factor and its module read it: the switch and the
 * parameters, and — for a factor that is on — the issuer resolved. A
 * switched-off factor keeps only an issuer written for it: the default is not
 * derived, so a factor nothing uses never refuses the boot over it.
 */
export type MfaTotpSettings = (TotpFactorSettings & {
    readonly enabled: true;
}) | (Omit<TotpFactorSettings, "issuer"> & {
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
    /** Recent MFA: how long, in seconds, a second factor verified in a session stays recent. */
    readonly manage: {
        readonly maxAgeSeconds: number;
    };
    /** Whether the account-email proof comes before a first binding (D24). */
    readonly enrollment: {
        readonly requireEmailProof: RequireEmailProof;
    };
    /** The records a subject may hold before an enrollment from its session is refused (F4): recovery codes are one. */
    readonly maxFactorsPerSubject: number;
    /** How long one Store call may take, in milliseconds: what a factor-set write's lease and deadline are made of (`factorSet.mts`). */
    readonly storeTimeoutMs: number;
}
/** What the settings read beside the `mfa` section. */
export interface MfaSettingsOptions {
    /**
     * The name the deployment selected its configuration by — the standalone
     * passes `CONFIG_ENV || NODE_ENV`. Read beside `NODE_ENV`, which is always
     * consulted, by the sample-key refusal: each that is set must say
     * development or test, and one must be set.
     */
    readonly environment?: string;
    /**
     * The replica count, as core's `deploymentMode` slot holds it — the MFA
     * module passes the slot's value. `multi` refuses the sample key; the
     * configuration's own `deployment` is not read. Anything but the three
     * values, absence included, is a TypeError.
     */
    readonly deploymentMode: DeploymentMode;
}
/**
 * The TOTP factor's section, `mfa-totp-factor` — what the TOTP factor's
 * module reads. A `RangeError` names each key refused. `options.issuer` is
 * the deployment's issuer — the `oauthTokenSettings` slot's — whose host an
 * unset TOTP issuer defaults to.
 */
export declare function readMfaTotpSettings(section: unknown, options?: {
    readonly issuer?: unknown;
}): MfaTotpSettings;
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
export declare function readMfaSettings(section: unknown, options: MfaSettingsOptions): MfaSettings;
//# sourceMappingURL=config.d.mts.map