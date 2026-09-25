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
 * The MFA configuration core owns (the MFA ADR's D19): `mfa.mode`, the
 * deployment's step-up page at `endpoints.mfa.url`, and the two store
 * switches a composition root installs MFA's stores from.
 *
 * `mfa.mode` is `"off"` by reference default, and `"off"` is the only value
 * this release can honour: no module here asks for or verifies a second
 * factor. A setting nothing can honour is refused at boot, naming its key,
 * rather than accepted and ignored — an operator who wrote `required` must
 * not believe their logins ask for a second factor.
 */

import { fileURLToPath } from "node:url";
import { parseFile } from "@o3co/ts.hocon";
import { validate } from "@o3co/ts.hocon/zod";
import { describe, expect, it } from "vitest";
import { BootError } from "#/boot/types.mjs";
import { AppConfigSchema, CoreConfigSchema } from "#/config/application.schema.mjs";
import { createApp } from "#/index.mjs";
import { makeValidAppConfig, makeValidCoreConfig } from "#/testing/fixtures/valid-config.mjs";

const REFERENCE_CONF = fileURLToPath(new URL("../../../config/reference.conf", import.meta.url));

const ENV = {
	OAUTH_JWT_SECRET: "mfa-schema-test.at-least-32-bytes.ok",
	OAUTH_JWT_ISSUER: "https://auth.test",
	SESSION_SECRET: "mfa-schema-test-session.at-least-32-bytes.ok",
};

const fromReference = (env: Record<string, string> = {}) =>
	validate(parseFile(REFERENCE_CONF, { env: { ...ENV, ...env } }), AppConfigSchema);

const issuesAt = (result: { success: boolean; error?: { issues: { path: PropertyKey[] }[] } }) =>
	result.success ? [] : (result.error?.issues ?? []).map((issue) => issue.path.join("."));

describe("the MFA configuration core owns (D19)", () => {
	it("resolves from reference.conf: mode off, the step-up page at /mfa, both stores in memory", () => {
		const config = fromReference();
		expect(config.mfa?.mode).toBe("off");
		expect(config.endpoints.mfa?.url).toBe("/mfa");
		expect(config.mfaFactorStore?.adapter).toBe("memory");
		expect(config.mfaTransactionStore?.adapter).toBe("memory");
	});

	it("reads each from its environment variable", () => {
		const config = fromReference({
			MFA_MODE: "off",
			ENDPOINTS_MFA_URL: "/account/mfa",
			MFA_FACTOR_STORE_ADAPTER: "store",
			MFA_TRANSACTION_STORE_ADAPTER: "redis",
		});
		expect(config.mfa?.mode).toBe("off");
		expect(config.endpoints.mfa?.url).toBe("/account/mfa");
		expect(config.mfaFactorStore?.adapter).toBe("store");
		expect(config.mfaTransactionStore?.adapter).toBe("redis");
	});

	it("refuses an mfa.mode this release cannot honour, naming the key", () => {
		for (const mode of ["required", "optional", "", "on", "OFF"]) {
			expect(() => fromReference({ MFA_MODE: mode }), mode).toThrow(/mfa\.mode/);
			expect(
				issuesAt(AppConfigSchema.safeParse({ ...makeValidAppConfig(), mfa: { mode } })),
				mode,
			).toContain("mfa.mode");
		}
	});

	it("refuses an mfa.mode that is written but unusable in a composition that never parsed AppConfigSchema", async () => {
		// createApp validates CoreConfigSchema itself, so a hand-built
		// configuration is refused too — before any module is built.
		expect(
			issuesAt(CoreConfigSchema.safeParse({ ...makeValidCoreConfig(), mfa: { mode: "required" } })),
		).toContain("mfa.mode");
		const err = await createApp({
			modules: [],
			bootstrapComponents: {
				config: { ...makeValidCoreConfig(), mfa: { mode: "required" } },
				pathResolver: (p: string) => p,
			} as never,
		}).then(
			() => undefined,
			(caught: unknown) => caught,
		);
		expect(err).toBeInstanceOf(BootError);
		expect((err as BootError).reason).toBe("config-validation-failed");
		const issues = (err as { details?: { issues?: { path: PropertyKey[] }[] } }).details?.issues;
		expect(issues?.map((issue) => issue.path.join("."))).toContain("mfa.mode");
	});

	it("keeps the rest of the mfa section for the package that owns it", () => {
		const parsed = CoreConfigSchema.parse({
			...makeValidCoreConfig(),
			mfa: { mode: "off", transactionTtlSeconds: 600 },
		}) as { mfa?: Record<string, unknown> };
		expect(parsed.mfa).toEqual({ mode: "off", transactionTtlSeconds: 600 });
	});

	it("accepts the factor store's three adapters and the transaction store's two, and nothing else", () => {
		for (const adapter of ["memory", "redis", "store"]) {
			expect(
				issuesAt(
					AppConfigSchema.safeParse({ ...makeValidAppConfig(), mfaFactorStore: { adapter } }),
				),
				adapter,
			).toEqual([]);
		}
		for (const adapter of ["memory", "redis"]) {
			expect(
				issuesAt(
					AppConfigSchema.safeParse({ ...makeValidAppConfig(), mfaTransactionStore: { adapter } }),
				),
				adapter,
			).toEqual([]);
		}
		// No Store variant for transactions: they are verification state.
		expect(
			issuesAt(
				AppConfigSchema.safeParse({
					...makeValidAppConfig(),
					mfaTransactionStore: { adapter: "store" },
				}),
			),
		).toContain("mfaTransactionStore.adapter");
		expect(
			issuesAt(
				AppConfigSchema.safeParse({ ...makeValidAppConfig(), mfaFactorStore: { adapter: "sql" } }),
			),
		).toContain("mfaFactorStore.adapter");
	});
});
