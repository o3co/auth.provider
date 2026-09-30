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
 * `webauthnMfaFactorModule` (the MFA ADR's D2, D4, D20): contributes the
 * `webauthn` second factor under core's `mfaFactors` kind, where the MFA
 * package's coordinator reads it through `mfaFactorResolver`; this package
 * imports nothing of the MFA package. Built from the relying party the
 * `webauthnConfig` slot holds and its own section, `webauthn-mfa-factor`,
 * which boot parses with the module's schema before any factory runs; it
 * answers `null` when `webauthn-mfa-factor.enabled` is false, which leaves
 * the kind claimed and absent from the resolver. Without the relying party
 * the boot is refused, naming the slot. Stateless: nothing forks per replica.
 */

import { defineModule } from "@o3co/auth-provider-core";
import { webauthnMfaFactorConfigSchema } from "./config.mjs";
import { createWebAuthnMfaFactor, WEBAUTHN_MFA_FACTOR_KIND } from "./factor.mjs";

/** The WebAuthn second factor, contributed as `mfaFactors.webauthn`; `null` when switched off by its section. */
export const webauthnMfaFactorModule = defineModule({
	name: "webauthn-mfa-factor",
	section: {
		schema: webauthnMfaFactorConfigSchema,
		reference: new URL("../../config/reference.conf", import.meta.url),
	},
	requires: ["webauthnConfig"] as const,
	contributes: {
		mfaFactors: {
			[WEBAUTHN_MFA_FACTOR_KIND]: ({ webauthnConfig, section }) =>
				section.enabled
					? createWebAuthnMfaFactor({
							relyingParty: webauthnConfig,
							userVerification: section.userVerification,
						})
					: null,
		},
	},
});
