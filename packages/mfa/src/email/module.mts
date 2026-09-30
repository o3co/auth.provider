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
 * `mfaEmailFactorModule`: the email factor's module (the MFA ADR's D1, F5),
 * named after its section, `mfa-email-factor`, which boot parses with the
 * module's schema before any factory runs. This build has no email factor:
 * the module claims the `email` kind under `mfaFactors`, answers no factor
 * while `mfa-email-factor.enabled` is false, and refuses the boot when it is
 * true, so switching the factor on never passes for having it. It requires
 * nothing, a mail sender included, so a composition with the factor off
 * boots without one. Stateless.
 */

import { defineModule } from "@o3co/auth-provider-core";
import { mfaEmailFactorConfigSchema } from "./config.mjs";

/** The kind an email factor's records carry, and the key it is contributed under. */
const EMAIL_FACTOR_KIND = "email";

/** The email factor's module: its section, and the `email` kind claimed. */
export const mfaEmailFactorModule = defineModule({
	name: "mfa-email-factor",
	section: {
		schema: mfaEmailFactorConfigSchema,
		reference: new URL("../../config/reference.conf", import.meta.url),
	},
	contributes: {
		mfaFactors: {
			[EMAIL_FACTOR_KIND]: ({ section }) => {
				if (!section.enabled) return null;
				throw new RangeError(
					"mfa-email-factor.enabled is true, and this build has no email factor to offer: set mfa-email-factor.enabled = false (MFA_EMAIL_FACTOR_ENABLED)",
				);
			},
		},
	},
});
