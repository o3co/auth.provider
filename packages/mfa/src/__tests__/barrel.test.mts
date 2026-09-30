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
 * The package's entry: what a composition root imports. The MFA module and
 * `mfaModules` — the TOTP factor's module beside it — with the id of the MFA
 * routes' contribution and the prefix their budget is keyed by, the TOTP
 * factor's module on its own, the schema of
 * the `mfa` keys this package reads, and the published development sample
 * key a development configuration may carry (the MFA ADR's D1 and D11). The
 * requirement, the transactions, the sealing, the TOTP primitive and the
 * settings reader are the package's own.
 */

import { describe, expect, it } from "vitest";
import * as entry from "#/index.mjs";

describe("@o3co/auth-provider-mfa's entry", () => {
	it("exports the MFA module, mfaModules, the routes' id and budget prefix, the TOTP factor's module, the MFA config schema and the development sample key, and nothing else", () => {
		expect(Object.keys(entry).sort()).toEqual([
			"MFA_DEVELOPMENT_SAMPLE_KEY",
			"MFA_RATE_LIMIT_PREFIX",
			"MFA_ROUTES_ID",
			"mfaConfigSchema",
			"mfaModule",
			"mfaModules",
			"mfaTotpFactorModule",
		]);
	});
});
