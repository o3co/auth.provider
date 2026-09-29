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
 * through `mfaFactorResolver`. Built from `mfa.factors.totp` alone — a factor
 * never holds a key, so the ring is not read here — and answering `null`
 * when `mfa.factors.totp.enabled` is false, which leaves the kind claimed and
 * absent from the resolver. A section it cannot read refuses the boot as a
 * failed contribution, naming the key. Stateless: nothing forks per replica.
 */

import { defineModule } from "@o3co/auth-provider-core";
import { z } from "zod";
import { readMfaTotpSettings } from "../config.mjs";
import { createTotpFactor, TOTP_FACTOR_KIND } from "./factor.mjs";

/** The TOTP factor, contributed as `mfaFactors.totp`; `null` when switched off by its configuration. */
export const mfaTotpFactorModule = defineModule({
	name: "mfa-totp-factor",
	// #728: the package's `config/reference.conf` holds this section's
	// defaults. Its schema checks nothing yet: the factor's factory reads the
	// section itself (`readMfaTotpSettings`) and refuses what it cannot use as
	// that factory's failure; the schema takes over when the section moves
	// under the module's name.
	section: {
		schema: z.unknown(),
		reference: new URL("../../config/reference.conf", import.meta.url),
		at: "mfa.factors.totp",
	},
	requires: ["config"] as const,
	contributes: {
		mfaFactors: {
			[TOTP_FACTOR_KIND]: ({ config }) => {
				const settings = readMfaTotpSettings(config);
				return settings.enabled ? createTotpFactor(settings) : null;
			},
		},
	},
});
