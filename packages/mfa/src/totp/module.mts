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
 * `mfaTotpFactorModule` (the MFA ADR's D1, D3, D19): contributes the `totp`
 * factor under core's `mfaFactors` kind, where the coordinator reads it
 * through `mfaFactorResolver`. Built from its own section, `mfa-totp-factor`,
 * alone — a factor never holds a key, so the ring is not read here — and
 * answering `null` when `mfa-totp-factor.enabled` is false, which leaves the
 * kind claimed and absent from the resolver. Boot parses the section with the
 * module's schema before any factory runs and refuses what it cannot read,
 * naming the key; a configuration still setting the section's old path,
 * `mfa.factors.totp`, is refused naming the new one, and so is an environment
 * setting a variable renamed with the move unless its new name carries the
 * same value. The whole configuration
 * is read for the deployment's issuer alone: `oauth.jwt.issuer` when no module
 * provides `oauthTokenSettings`, and core's check of the slot when one does.
 * Stateless: nothing forks per replica.
 */

import { checkOAuthTokenSettings, defineModule } from "@o3co/auth-provider-core";
import { mfaTotpConfigSchema, readMfaTotpSettings } from "../config.mjs";
import { createTotpFactor, TOTP_FACTOR_KIND } from "./factor.mjs";

/** `oauth.jwt.issuer` as the configuration carries it. */
const configuredIssuer = (config: unknown): unknown =>
	(config as { oauth?: { jwt?: { issuer?: unknown } } } | undefined)?.oauth?.jwt?.issuer;

/** The TOTP factor, contributed as `mfaFactors.totp`; `null` when switched off by its configuration. */
export const mfaTotpFactorModule = defineModule({
	name: "mfa-totp-factor",
	// The package's `config/reference.conf` holds this section's defaults,
	// binds each key's variable at its new path and nothing at the old one,
	// and captures the renamed variables' old and new names.
	section: {
		schema: mfaTotpConfigSchema,
		reference: new URL("../../config/reference.conf", import.meta.url),
		relocatedFrom: ["mfa.factors.totp"],
		renamedVariables: {
			MFA_TOTP_ENABLED: "mfa.factors.totp.enabled",
			MFA_TOTP_ISSUER: "mfa.factors.totp.issuer",
		},
	},
	requires: ["config"] as const,
	// The issuer an unset TOTP issuer defaults to the host of, which the
	// oauth module provides; `oauth.jwt.issuer` when no module does.
	optional: ["oauthTokenSettings"] as const,
	contributes: {
		mfaFactors: {
			[TOTP_FACTOR_KIND]: ({ config, oauthTokenSettings, section }) => {
				const settings = readMfaTotpSettings(section, {
					// The slot whole, checked first: its issuer is then
					// always one, so the configuration's is read only without it.
					issuer:
						oauthTokenSettings === undefined
							? configuredIssuer(config)
							: checkOAuthTokenSettings(oauthTokenSettings, config).issuer,
				});
				return settings.enabled ? createTotpFactor(settings) : null;
			},
		},
	},
});
