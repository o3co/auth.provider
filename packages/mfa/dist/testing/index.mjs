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
 * one, so none writes its sections or seals its data by hand. The four
 * sections its modules read, each as a configuration fragment at the
 * section's name with the reference defaults; a factor of any kind stored as
 * an enrollment leaves it, and its data sealed and opened, under a
 * configuration's key ring; a TOTP factor so stored; and the codes that
 * factor takes. For tests only.
 */
import { randomBytes } from "node:crypto";
import { readConditionalCreateAnswer, readMfaFactorSet, } from "@o3co/auth-provider-core";
import { readMfaSettings } from "../config.mjs";
import { createMfaSealing } from "../sealing.mjs";
import { encodeBase32 } from "../totp/base32.mjs";
import { TOTP_FACTOR_KIND } from "../totp/factor.mjs";
import { hotp, totpStep } from "../totp/rfc6238.mjs";
/**
 * The MFA module's section, `mfa`, as the package's reference.conf resolves
 * it, with `options` laid over it. The mode is `off` unless given, as there.
 */
export function mfaConfigForTests(options) {
    const { key, encryptionKeys, lockout, ...rest } = options;
    return {
        mfa: {
            mode: "off",
            page: { url: "/mfa" },
            transactionTtlSeconds: 600,
            maxAttemptsPerTransaction: 5,
            manage: { maxAgeSeconds: 300 },
            enrollment: { requireEmailProof: "when-mail" },
            maxFactorsPerSubject: 10,
            storeTimeoutMs: 5_000,
            ...rest,
            encryptionKeys: encryptionKeys?.map((entry) => ({ ...entry })) ?? [{ key }],
            lockout: {
                threshold: 5,
                baseSeconds: 900,
                maxSeconds: 86_400,
                memorySeconds: 86_400,
                weeklyBudget: 10,
                hardLimit: 100,
                ...lockout,
            },
        },
    };
}
/** The TOTP factor's section, `mfa-totp-factor`, as the package's reference.conf resolves it, with `options` laid over it. */
export function mfaTotpFactorConfigForTests(options = {}) {
    return {
        "mfa-totp-factor": {
            enabled: true,
            algorithm: "SHA1",
            digits: 6,
            period: 30,
            window: 1,
            ...options,
        },
    };
}
/** The recovery-code factor's section, `mfa-recovery-code-factor`, as the package's reference.conf resolves it, with `options` laid over it. */
export function mfaRecoveryCodeFactorConfigForTests(options = {}) {
    return { "mfa-recovery-code-factor": { enabled: true, count: 10, ...options } };
}
/** The email factor's section, `mfa-email-factor`, as the package's reference.conf resolves it, with `options` laid over it. */
export function mfaEmailFactorConfigForTests(options = {}) {
    return {
        "mfa-email-factor": { enabled: false, addsMfa: false, codeTtlSeconds: 600, ...options },
    };
}
/** The sealing the MFA module builds from the MFA section `config` holds: the same key ring. */
function sealingOf(config) {
    const section = config?.mfa;
    const { encryptionKeys } = readMfaSettings(section, { deploymentMode: "unset" });
    return createMfaSealing({ ring: encryptionKeys });
}
/**
 * `data` sealed for the record `bound` names, under the key ring of the MFA
 * section `config` holds, as the coordinator seals a factor's data.
 */
export function sealMfaFactorDataForTests(config, bound, data) {
    return sealingOf(config).sealFactorData(bound, data);
}
/**
 * The data of `record` opened under the key ring of the MFA section `config`
 * holds, as the coordinator opens it. Throws when it does not open.
 */
export function openMfaFactorDataForTests(config, record) {
    const opened = sealingOf(config).openFactorData(record, record.data);
    if (opened.state !== "ok") {
        throw new Error(`the factor's data does not open: ${opened.state}`);
    }
    return opened.value;
}
/**
 * `record` added to its subject's set in `store` as a writer of the set adds
 * one: by `createIf`, at the generation the set is read at. Throws when the
 * store refuses it — another write landed meanwhile, or the id is held.
 */
async function addToSet(store, record) {
    const { generation } = readMfaFactorSet(await store.listVersioned(record.subject), record.subject);
    const answer = readConditionalCreateAnswer(await store.createIf(record, generation));
    if (answer.outcome !== "created") {
        throw new Error("the factor was not stored: the subject's set changed, or its id is held");
    }
}
/**
 * Stores a factor of `kind` for `subject`, its data sealed to its record
 * under the ring of `config`'s MFA section, as an enrollment by password
 * leaves it a day ago. Answers the record stored.
 */
export async function seedMfaFactor(options) {
    const id = options.id ?? randomBytes(16).toString("base64url");
    const bound = { subject: options.subject, id, kind: options.kind };
    const record = {
        id,
        subject: options.subject,
        kind: options.kind,
        label: options.label,
        binding: "password",
        createdAt: new Date(Date.now() - 86_400_000),
        lastUsedAt: undefined,
        version: 0,
        data: sealMfaFactorDataForTests(options.config, bound, options.data),
    };
    await addToSet(options.factorStore, record);
    return record;
}
/**
 * Stores a TOTP factor for `subject` — SHA1, 6 digits, 30-second steps —
 * its data sealed under the ring of `config`'s MFA section, as an enrollment
 * leaves it. Answers the record stored and the secret.
 */
export async function seedTotpFactor(options) {
    const section = options.config?.mfa;
    const { encryptionKeys } = readMfaSettings(section, { deploymentMode: "unset" });
    const secret = options.secret ?? randomBytes(20);
    const id = options.id ?? randomBytes(16).toString("base64url");
    const record = {
        id,
        subject: options.subject,
        kind: TOTP_FACTOR_KIND,
        label: options.label,
        binding: "password",
        createdAt: new Date(Date.now() - 86_400_000),
        lastUsedAt: undefined,
        version: 0,
        data: createMfaSealing({ ring: encryptionKeys }).sealFactorData({ subject: options.sealedFor ?? options.subject, id, kind: TOTP_FACTOR_KIND }, {
            secret: encodeBase32(secret),
            algorithm: "SHA1",
            digits: 6,
            period: 30,
            lastUsedStep: options.lastUsedStep ?? 0,
        }),
    };
    await addToSet(options.factorStore, record);
    return { record, secret };
}
/**
 * The code a factor {@link seedTotpFactor} stored takes: RFC 6238 over
 * `secret` at `atMs` (now unless given), `offset` steps away.
 */
export function totpCodeForTests(secret, options = {}) {
    const step = totpStep(options.atMs ?? Date.now(), 30) + (options.offset ?? 0);
    return hotp(secret, step, { algorithm: "SHA1", digits: 6 });
}
