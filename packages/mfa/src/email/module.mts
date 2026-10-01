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
 * `mfaEmailFactorModule`: the email factor's module (the MFA ADR's D1, D20,
 * F5), named after its section, `mfa-email-factor`, which boot parses with
 * the module's schema before any factory runs. It contributes the factor as
 * `mfaFactors.email`, built from the section, and `null` while `enabled` is
 * false, which leaves the kind claimed and absent from the resolver. It reads
 * the `mailSender` slot optionally: with the factor off a composition boots
 * without one; switched on without one, the boot is refused naming the
 * switch and the slot, so the factor is never offered with no way to send
 * its codes. Stateless.
 */

import { defineModule } from "@o3co/auth-provider-core";
import { mfaEmailFactorConfigSchema } from "./config.mjs";
import { createEmailFactor, EMAIL_FACTOR_KIND } from "./factor.mjs";

/** The email factor's module: its section, and the factor built from it. */
export const mfaEmailFactorModule = defineModule({
	name: "mfa-email-factor",
	section: {
		schema: mfaEmailFactorConfigSchema,
		reference: new URL("../../config/reference.conf", import.meta.url),
	},
	optional: ["mailSender"] as const,
	contributes: {
		mfaFactors: {
			[EMAIL_FACTOR_KIND]: ({ section, mailSender }) => {
				if (!section.enabled) return null;
				if (mailSender === undefined) {
					throw new RangeError(
						"mfa-email-factor.enabled (MFA_EMAIL_FACTOR_ENABLED) is true and no module provides the mailSender slot: the email factor could send no code — wire a mail sender, or set mfa-email-factor.enabled = false",
					);
				}
				return createEmailFactor({
					addsMfa: section.addsMfa,
					codeTtlSeconds: section.codeTtlSeconds,
				});
			},
		},
	},
});
