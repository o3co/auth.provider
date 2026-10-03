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
 * `webauthnMfaFactorModule`: contributes the
 * `webauthn` second factor under core's `mfaFactors` kind, where the MFA
 * package's coordinator reads it through `mfaFactorResolver`; this package
 * imports nothing of the MFA package. Built from the relying party the
 * `webauthnConfig` slot holds (which `webauthnModule` provides from its
 * section) and its own section, `webauthn-mfa-factor`,
 * which boot parses with the module's schema before any factory runs.
 * `webauthn-mfa-factor.enabled` is the module's switch (`section.isEnabled`):
 * false, and the module registers nothing. The relying party is taken when
 * wired: off, the module boots without it; on without it, the factory
 * refuses, naming the slot and the keys it is built from. Stateless: nothing
 * forks per replica.
 */

import { defineModule } from "@o3co/auth-provider-core";
import { webauthnMfaFactorConfigSchema } from "./config.mjs";
import { createWebAuthnMfaFactor, WEBAUTHN_MFA_FACTOR_KIND } from "./factor.mjs";

/** The WebAuthn second factor, contributed as `mfaFactors.webauthn`; nothing when switched off by its section. */
export const webauthnMfaFactorModule = defineModule({
	name: "webauthn-mfa-factor",
	section: {
		schema: webauthnMfaFactorConfigSchema,
		reference: new URL("../../config/reference.conf", import.meta.url),
		isEnabled: (section) => section.enabled,
	},
	// Needed only when the factor is on, so a composition may install the
	// module and leave the factor off without a relying party.
	optional: ["webauthnConfig"] as const,
	contributes: {
		mfaFactors: {
			[WEBAUTHN_MFA_FACTOR_KIND]: ({ webauthnConfig, section }) => {
				if (!section.enabled) return null;
				if (webauthnConfig === undefined) {
					throw new Error(
						"webauthnMfaFactorModule: webauthn-mfa-factor.enabled = true requires the " +
							"webauthnConfig component — the relying party, built from webauthn.rpId, " +
							"webauthn.rpName and webauthn.origin, which webauthnModule provides from its " +
							"section. Install webauthnModule (or, without it, provide the slot), or leave " +
							"the factor off " +
							"(WEBAUTHN_MFA_FACTOR_ENABLED).",
					);
				}
				return createWebAuthnMfaFactor({
					relyingParty: webauthnConfig,
					userVerification: section.userVerification,
				});
			},
		},
	},
});
