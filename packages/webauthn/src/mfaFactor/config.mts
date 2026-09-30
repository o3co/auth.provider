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
 * The section of the WebAuthn second factor's module, `webauthn-mfa-factor`
 * (the MFA ADR's D4, D19, F7): its switch, and the user verification a
 * registration asks for — `required`, `preferred` or `discouraged`, WebAuthn's
 * values. Strict: a key the section does not know is refused. Every leaf
 * reads the string an environment variable carries: `enabled` through core's
 * `coerceBooleanFromEnv`, from `WEBAUTHN_MFA_FACTOR_ENABLED`, and
 * `userVerification` from `WEBAUTHN_MFA_FACTOR_USER_VERIFICATION`. Its
 * defaults — off, `preferred` — are not in the package's reference.conf: no
 * module of the package reads the section, and a section there that no
 * installed module owns is named ignored at every boot. Not on the package's
 * entry.
 */

import { coerceBooleanFromEnv } from "@o3co/auth-provider-core";
import { z } from "zod";

/** The WebAuthn second factor's section, as its module is to parse it before any factory runs. */
export const webauthnMfaFactorConfigSchema = z.strictObject(
	{
		enabled: coerceBooleanFromEnv,
		userVerification: z.enum(["required", "preferred", "discouraged"], {
			error: 'must be "required", "preferred" or "discouraged"',
		}),
	},
	{
		error: (issue) =>
			issue.code === "unrecognized_keys"
				? `has a key it does not know: ${issue.keys.join(", ")}`
				: "must be a section of keys",
	},
);

/** `webauthn-mfa-factor` as its schema reads it. */
export type WebAuthnMfaFactorSettings = z.infer<typeof webauthnMfaFactorConfigSchema>;
