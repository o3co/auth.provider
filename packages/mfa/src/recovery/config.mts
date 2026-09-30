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
 * The recovery-code factor's section, `mfa-recovery-code-factor` (the MFA
 * ADR's D19, D22, D25): its switch, and how many codes a set holds — 1 to 20,
 * a range the ADR does not state. Strict: a key the section does not know is
 * refused. Every leaf reads the string an environment variable carries.
 */

import { coerceBooleanFromEnv } from "@o3co/auth-provider-core";
import { z } from "zod";
import { environmentWholeNumber, sectionError } from "../config.mjs";

/** The recovery-code factor's section, as its module parses it before any factory runs. */
export const mfaRecoveryCodeFactorConfigSchema = z.strictObject(
	{
		enabled: coerceBooleanFromEnv,
		count: environmentWholeNumber(1, 20, " codes"),
	},
	{ error: sectionError },
);

/** `mfa-recovery-code-factor` as its schema reads it. */
export type MfaRecoveryCodeFactorSettings = z.infer<typeof mfaRecoveryCodeFactorConfigSchema>;
