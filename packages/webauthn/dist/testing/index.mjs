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
import { webauthnConfigSchema } from "../config.mjs";
import { WEBAUTHN_MFA_FACTOR_KIND, } from "../mfaFactor/factor.mjs";
/**
 * The `webauthn` section as `webauthnConfigSchema` parses it, for a test relying party
 * (`rpId` `test.example`, origin `https://test.example`), with `overrides` applied before the
 * parse, so a value the schema refuses fails the test that built it. Its values are a test's,
 * not the deployment's defaults, which are `config/reference.conf`'s.
 */
export function createTestWebAuthnConfig(overrides = {}) {
    return webauthnConfigSchema.parse({
        rpId: "test.example",
        rpName: "Test",
        origin: ["https://test.example"],
        challengeTtlMs: 120_000,
        attestationPreference: "none",
        userVerification: "preferred",
        ...overrides,
    });
}
/**
 * The WebAuthn second factor's section, `webauthn-mfa-factor`, as the package's reference.conf
 * resolves it — off, user verification `preferred` — with `options` laid over it.
 */
export function webauthnMfaFactorConfigForTests(options = {}) {
    return {
        "webauthn-mfa-factor": {
            enabled: false,
            userVerification: "preferred",
            ...options,
        },
    };
}
/**
 * A WebAuthn second factor as an enrollment leaves it: the kind its record carries, and its data
 * as the factor reads it — for a test to seed through the MFA package's `seedMfaFactor`.
 */
export function webauthnMfaFactorDataForTests(options) {
    return {
        kind: WEBAUTHN_MFA_FACTOR_KIND,
        data: {
            credentialId: options.credentialId,
            publicKey: Buffer.from(options.publicKey).toString("base64url"),
            signCount: options.signCount ?? 0,
            transports: [...(options.transports ?? ["internal"])],
            backupEligible: options.backupEligible ?? false,
            backedUp: options.backedUp ?? false,
            userHandle: options.userHandle,
        },
    };
}
