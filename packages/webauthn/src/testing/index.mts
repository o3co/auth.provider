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
 * The WebAuthn package's testing entry (`@o3co/auth-provider-webauthn/testing`): what a test
 * builds this package's configuration with, so no test writes the `webauthn` or the
 * `webauthn-mfa-factor` section by hand, and a WebAuthn second factor as an enrollment leaves
 * it, so no test writes the factor's data by hand.
 */

import type { AuthenticatorTransport, MfaFactorData } from "@o3co/auth-provider-core";
import { type WebAuthnConfig, webauthnConfigSchema } from "../config.mjs";
import {
	type UserVerificationRequirement,
	WEBAUTHN_MFA_FACTOR_KIND,
} from "../mfaFactor/factor.mjs";

/**
 * The `webauthn` section as `webauthnConfigSchema` parses it, for a test relying party
 * (`rpId` `test.example`, origin `https://test.example`), with `overrides` applied before the
 * parse, so a value the schema refuses fails the test that built it. Its values are a test's,
 * not the deployment's defaults, which are `config/reference.conf`'s.
 */
export function createTestWebAuthnConfig(overrides: Partial<WebAuthnConfig> = {}): WebAuthnConfig {
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

/** What {@link webauthnMfaFactorConfigForTests} lays over the reference defaults. */
export interface WebAuthnMfaFactorConfigForTestsOptions {
	readonly enabled?: boolean;
	readonly userVerification?: UserVerificationRequirement;
}

/**
 * The WebAuthn second factor's section, `webauthn-mfa-factor`, as the package's reference.conf
 * resolves it — off, user verification `preferred` — with `options` laid over it.
 */
export function webauthnMfaFactorConfigForTests(
	options: WebAuthnMfaFactorConfigForTestsOptions = {},
) {
	return {
		"webauthn-mfa-factor": {
			enabled: false,
			userVerification: "preferred" as UserVerificationRequirement,
			...options,
		},
	};
}

/** What {@link webauthnMfaFactorDataForTests} builds a WebAuthn factor from. */
export interface WebAuthnMfaFactorDataForTestsOptions {
	/** The credential id, base64url. */
	readonly credentialId: string;
	/** The COSE public key. */
	readonly publicKey: Uint8Array;
	/** The subject's WebAuthn user handle, base64url. */
	readonly userHandle: string;
	/** The sign count; 0 unless given. */
	readonly signCount?: number;
	/** `["internal"]` unless given. */
	readonly transports?: readonly AuthenticatorTransport[];
	/** Backup-eligible (BE), a multi-device credential; false unless given. */
	readonly backupEligible?: boolean;
	/** Backed up (BS); false unless given. */
	readonly backedUp?: boolean;
}

/**
 * A WebAuthn second factor as an enrollment leaves it: the kind its record carries, and its data
 * as the factor reads it — for a test to seed through the MFA package's `seedMfaFactor`.
 */
export function webauthnMfaFactorDataForTests(options: WebAuthnMfaFactorDataForTestsOptions): {
	readonly kind: string;
	readonly data: MfaFactorData;
} {
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
