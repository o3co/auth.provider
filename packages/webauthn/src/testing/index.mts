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
 * The WebAuthn package's testing entry (`@o3co/auth-provider-webauthn/testing`): what a test
 * builds this package's configuration with, so no test writes the `webauthn` section by hand.
 */

import { type WebAuthnConfig, webauthnConfigSchema } from "../config.mjs";

/**
 * The `webauthn` section as `webauthnConfigSchema` parses it, for a test relying party
 * (`rpId` `test.example`, origin `https://test.example`), with `overrides` applied before the
 * parse, so a value the schema refuses fails the test that built it. Its values are a test's,
 * not the deployment's defaults, which are `config/reference.conf`'s.
 */
export function createTestWebAuthnConfig(overrides: Partial<WebAuthnConfig> = {}): WebAuthnConfig {
	return webauthnConfigSchema.parse({
		rpId: "test.example",
		rpName: "Test",
		origin: ["https://test.example"],
		challengeTtlMs: 120_000,
		attestationPreference: "none",
		userVerification: "preferred",
		allowCredentialsForKnownUser: false,
		rateLimit: { authenticationOptions: { limit: 1000, windowSeconds: 60 } },
		...overrides,
	});
}
