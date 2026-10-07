import { type MfaFactorData, type MfaFactorRecord, type MfaFactorStore, type MfaLockoutPolicy } from "@o3co/auth-provider-core";
import { type TotpAlgorithm } from "../totp/rfc6238.mjs";
/** What {@link mfaConfigForTests} lays over the reference defaults. */
export interface MfaConfigForTestsOptions {
    /** The ring's one key: canonical base64 of 32 bytes. */
    readonly key: string;
    readonly mode?: "off" | "optional" | "required";
    readonly page?: {
        readonly url: string;
    };
    /** The whole ring, in place of `key`'s. */
    readonly encryptionKeys?: readonly {
        readonly id?: string;
        readonly key?: string;
    }[];
    readonly transactionTtlSeconds?: number;
    readonly maxAttemptsPerTransaction?: number;
    readonly lockout?: Partial<MfaLockoutPolicy>;
    readonly manage?: {
        readonly maxAgeSeconds: number;
    };
    readonly enrollment?: {
        readonly requireEmailProof: "when-mail" | "always" | "never";
    };
    readonly maxFactorsPerSubject?: number;
    /** `mfa.storeTimeoutMs`: how long one Store call may take. */
    readonly storeTimeoutMs?: number;
}
/**
 * The MFA module's section, `mfa`, as the package's reference.conf resolves
 * it, with `options` laid over it. The mode is `off` unless given, as there.
 */
export declare function mfaConfigForTests(options: MfaConfigForTestsOptions): {
    mfa: {
        encryptionKeys: {
            id?: string;
            key?: string;
        }[];
        lockout: {
            threshold: number;
            baseSeconds: number;
            maxSeconds: number;
            memorySeconds: number;
            weeklyBudget: number;
            hardLimit: number;
        };
        mode: "off" | "optional" | "required";
        page: {
            readonly url: string;
        };
        transactionTtlSeconds: number;
        maxAttemptsPerTransaction: number;
        manage: {
            readonly maxAgeSeconds: number;
        };
        enrollment: {
            readonly requireEmailProof: "when-mail" | "always" | "never";
        };
        maxFactorsPerSubject: number;
        storeTimeoutMs: number;
    };
};
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
export declare function mfaTotpFactorConfigForTests(options?: MfaTotpFactorConfigForTestsOptions): {
    "mfa-totp-factor": {
        enabled: boolean;
        algorithm: TotpAlgorithm;
        digits: number;
        period: number;
        window: number;
        issuer?: string;
    };
};
/** The recovery-code factor's section, `mfa-recovery-code-factor`, as the package's reference.conf resolves it, with `options` laid over it. */
export declare function mfaRecoveryCodeFactorConfigForTests(options?: {
    readonly enabled?: boolean;
    readonly count?: number;
}): {
    "mfa-recovery-code-factor": {
        enabled: boolean;
        count: number;
    };
};
/** What {@link mfaEmailFactorConfigForTests} lays over the reference defaults. */
export interface MfaEmailFactorConfigForTestsOptions {
    readonly enabled?: boolean;
    readonly addsMfa?: boolean;
    readonly codeTtlSeconds?: number;
}
/** The email factor's section, `mfa-email-factor`, as the package's reference.conf resolves it, with `options` laid over it. */
export declare function mfaEmailFactorConfigForTests(options?: MfaEmailFactorConfigForTestsOptions): {
    "mfa-email-factor": {
        enabled: boolean;
        addsMfa: boolean;
        codeTtlSeconds: number;
    };
};
/** A factor record's binding: what its sealed data is bound to. */
export interface MfaFactorBindingForTests {
    readonly subject: string;
    readonly id: string;
    readonly kind: string;
}
/**
 * `data` sealed for the record `bound` names, under the key ring of the MFA
 * section `config` holds, as the coordinator seals a factor's data.
 */
export declare function sealMfaFactorDataForTests(config: unknown, bound: MfaFactorBindingForTests, data: MfaFactorData): string;
/**
 * The data of `record` opened under the key ring of the MFA section `config`
 * holds, as the coordinator opens it. Throws when it does not open.
 */
export declare function openMfaFactorDataForTests(config: unknown, record: MfaFactorBindingForTests & {
    readonly data: string;
}): MfaFactorData;
/** What {@link seedMfaFactor} stores. */
export interface SeedMfaFactorOptions {
    /** A configuration holding the MFA module's section: its key ring seals the data. */
    readonly config: unknown;
    readonly factorStore: MfaFactorStore;
    readonly subject: string;
    readonly kind: string;
    /** The factor's own data, as its factor reads it. */
    readonly data: MfaFactorData;
    /** A fresh factor id unless given. */
    readonly id?: string;
    readonly label?: string;
}
/**
 * Stores a factor of `kind` for `subject`, its data sealed to its record
 * under the ring of `config`'s MFA section, as an enrollment by password
 * leaves it a day ago. Answers the record stored.
 */
export declare function seedMfaFactor(options: SeedMfaFactorOptions): Promise<MfaFactorRecord>;
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
export declare function seedTotpFactor(options: SeedTotpFactorOptions): Promise<{
    readonly record: MfaFactorRecord;
    readonly secret: Buffer;
}>;
/**
 * The code a factor {@link seedTotpFactor} stored takes: RFC 6238 over
 * `secret` at `atMs` (now unless given), `offset` steps away.
 */
export declare function totpCodeForTests(secret: Buffer, options?: {
    readonly atMs?: number;
    readonly offset?: number;
}): string;
//# sourceMappingURL=index.d.mts.map