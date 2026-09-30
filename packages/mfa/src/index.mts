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

// @o3co/auth-provider-mfa — multi-factor authentication (the MFA ADR,
// packages/core/docs/adr/2026-09-25-multi-factor-authentication.md).
// Private until the standalone template wires it (the ADR's build-order
// step 20).

// The admission actions the package's routes admit, with their grades:
// declared, and registered by the module whose route admits one.
export { MFA_ADMISSION_ACTIONS, type MfaAdmissionAction } from "./admissionActions.mjs";
// The `mfa` keys this package reads, and the published development key a
// development configuration may carry (the MFA ADR's D11, D19).
export { MFA_DEVELOPMENT_SAMPLE_KEY, mfaConfigSchema } from "./config.mjs";
// The MFA module — the `mfa` session requirement, the MFA routes' mount and
// their budget's prefix — and what a composition lists to install MFA (the
// MFA ADR's D1; the session-admission ADR's D6).
export {
	MFA_RATE_LIMIT_PREFIX,
	MFA_ROUTES_ID,
	type MfaModuleOptions,
	mfaModule,
	mfaModules,
} from "./module.mjs";
// The recovery-code factor's module (the MFA ADR's D25), with its section.
export { mfaRecoveryCodeFactorModule } from "./recovery/module.mjs";
// The TOTP factor, contributed as `mfaFactors.totp` (the MFA ADR's F6).
export { mfaTotpFactorModule } from "./totp/module.mjs";
