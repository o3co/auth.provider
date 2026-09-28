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

// The `mfa` keys this package reads, and the published development key a
// development configuration may carry (D11, D19).
export { MFA_DEVELOPMENT_SAMPLE_KEY, mfaConfigSchema } from "./config.mjs";
// The TOTP factor, contributed as `mfaFactors.totp` (F6).
export { mfaTotpFactorModule } from "./totp/module.mjs";
