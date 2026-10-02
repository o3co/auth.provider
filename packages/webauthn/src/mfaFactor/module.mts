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
 * `webauthnConfig` slot holds and its own section, `webauthn-mfa-factor`,
 * which boot parses with the module's schema before any factory runs; it
 * answers `null` when `webauthn-mfa-factor.enabled` is false, which leaves
 * the kind claimed and absent from the resolver. The relying party is taken
 * when wired: off, the module boots without it; on without it, the factory
 * refuses, naming the slot and the keys it is built from. Installed while the
 * relying party has `allowCredentialsForKnownUser` on, on or off, the factory
 * refuses: a second factor's credential that returns no user handle could
 * then sign its owner in, through the grant, as another account that
 * registered it. Stateless: nothing forks per replica.
 *
 * It deliberately declares no `section.isEnabled`, the exception to "a
 * disabled module registers nothing": switched off by its section it would
 * run no check, and the second-factor credentials registered while it was on
 * outlive the switch, so the refusal must run whether the factor is on or off.
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
	// Needed only when the factor is on, so a composition may install the
	// module and leave the factor off without a relying party.
	optional: ["webauthnConfig"] as const,
	contributes: {
		mfaFactors: {
			[WEBAUTHN_MFA_FACTOR_KIND]: ({ webauthnConfig, section }) => {
				if (webauthnConfig?.allowCredentialsForKnownUser === true) {
					throw new Error(
						"webauthnMfaFactorModule: webauthn.allowCredentialsForKnownUser " +
							"(WEBAUTHN_ALLOW_CREDENTIALS_FOR_KNOWN_USER) is on while the WebAuthn second " +
							"factor is installed. With both, a second factor's credential that returns no " +
							"user handle can be registered by another account as its passkey, and then sign " +
							"its owner in as that account through the passwordless grant. Turn " +
							"allowCredentialsForKnownUser off, or remove webauthnMfaFactorModule.",
					);
				}
				if (!section.enabled) return null;
				if (webauthnConfig === undefined) {
					throw new Error(
						"webauthnMfaFactorModule: webauthn-mfa-factor.enabled = true requires the " +
							"webauthnConfig component — the relying party, built from webauthn.rpId, " +
							"webauthn.rpName and webauthn.origin, which the deployment's WebAuthn bootstrap " +
							"module provides. Provide it, or leave the factor off " +
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
