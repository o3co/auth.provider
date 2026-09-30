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
 * The MFA package's testing entry (`@o3co/auth-provider-mfa/testing`): what a test builds this
 * package's configuration with, so no test writes the MFA module's section by hand.
 */

import { randomBytes } from "node:crypto";
import type { z } from "zod";
import { mfaConfigSchema } from "../config.mjs";

/** The MFA module's section as {@link mfaConfigSchema} parses it. */
export type TestMfaConfig = z.infer<typeof mfaConfigSchema>;

/**
 * The MFA module's section as `mfaConfigSchema` parses it, for a test — `required`, the page at
 * `/mfa`, a ring of one fresh random key — with `overrides` applied before the parse, so a value
 * the schema refuses fails the test that built it. Its values are a test's, not the deployment's
 * defaults, which are `config/reference.conf`'s.
 */
export function createTestMfaConfig(overrides: Partial<TestMfaConfig> = {}): TestMfaConfig {
	return mfaConfigSchema.parse({
		mode: "required",
		page: { url: "/mfa" },
		encryptionKeys: [{ key: randomBytes(32).toString("base64") }],
		transactionTtlSeconds: 600,
		maxAttemptsPerTransaction: 5,
		lockout: {
			threshold: 5,
			baseSeconds: 900,
			maxSeconds: 86_400,
			memorySeconds: 86_400,
			weeklyBudget: 10,
			hardLimit: 100,
			trustedBrowsers: 5,
			trustedBrowserDays: 30,
		},
		manage: { maxAgeSeconds: 300 },
		...overrides,
	});
}
