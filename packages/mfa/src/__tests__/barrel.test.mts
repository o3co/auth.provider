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
 * The package's entry: what a composition root imports. The TOTP factor's
 * module, the schema of the `mfa` keys this package reads, and the published
 * development sample key a development configuration may carry (the MFA ADR's
 * D11, and the step-8 plan's public exports). The coordinator's sealing, the
 * TOTP primitive and the settings reader are the package's own.
 */

import { describe, expect, it } from "vitest";
import * as entry from "#/index.mjs";

describe("@o3co/auth-provider-mfa's entry", () => {
	it("exports the TOTP factor's module, the MFA config schema and the development sample key, and nothing else", () => {
		expect(Object.keys(entry).sort()).toEqual([
			"MFA_DEVELOPMENT_SAMPLE_KEY",
			"mfaConfigSchema",
			"mfaTotpFactorModule",
		]);
	});
});
