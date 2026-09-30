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
 * The email factor's section, `mfa-email-factor` (the MFA ADR's D19, F5):
 * its switch, whether a verification adds `mfa`, and a code's life — 60 to
 * 1800 seconds, as a transaction's. Nothing of the mail, which the sender
 * renders, and no limit on sending, which is the sender's. Strict: a key the
 * section does not know is refused by its name. Every leaf reads the string
 * an environment variable carries.
 */

import { coerceBooleanFromEnv } from "@o3co/auth-provider-core";
import { z } from "zod";
import { environmentWholeNumber, sectionError } from "../config.mjs";

/** The email factor's section, as its module parses it before any factory runs. */
export const mfaEmailFactorConfigSchema = z.strictObject(
	{
		enabled: coerceBooleanFromEnv,
		addsMfa: coerceBooleanFromEnv,
		codeTtlSeconds: environmentWholeNumber(60, 1800, " seconds"),
	},
	{ error: sectionError },
);

/** `mfa-email-factor` as its schema reads it. */
export type MfaEmailFactorSettings = z.infer<typeof mfaEmailFactorConfigSchema>;
