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

import { resolveDeviceVerificationLimitSpec } from "./deviceVerificationSpec.mjs";
import { resolveLoginLimitSpec } from "./loginSpec.mjs";
import { resolveMfaLimitSpecs } from "./mfaSpec.mjs";
import type { RateLimitSpec } from "./types.mjs";
import { resolveWebAuthnAuthenticationOptionsLimitSpec } from "./webauthnSpec.mjs";

/**
 * Every per-endpoint spec that lives in its own config slice, seeded into an
 * adapter's `limits` in one call. Both bundled adapter modules (memory here,
 * redis in `@o3co/auth-provider-redis`) call this, so a seed cannot be
 * forgotten in one of them. Prefixes: `login` (`rateLimit.login`),
 * `device_verification` (`oauth.deviceAuthorization.rateLimit`),
 * `webauthn-authentication-options` (`webauthn.rateLimit.authenticationOptions`),
 * `mfa` (`mfa.rateLimit.routes`) and `mfa-email`
 * (`mfa.factors.email.sendLimit`). An operator-declared entry for any prefix
 * still wins.
 */
export const resolveSeededLimitSpecs = (
	limits: Readonly<Record<string, RateLimitSpec>>,
	config: unknown,
): Record<string, RateLimitSpec> =>
	resolveMfaLimitSpecs(
		resolveWebAuthnAuthenticationOptionsLimitSpec(
			resolveDeviceVerificationLimitSpec(resolveLoginLimitSpec(limits, config), config),
			config,
		),
		config,
	);
