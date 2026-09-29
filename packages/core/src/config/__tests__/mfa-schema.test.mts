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
 * The MFA configuration core owns (ADR 2026-09-25-multi-factor-authentication):
 * `mfa.mode`, the deployment's step-up page at `endpoints.mfa.url`, the two
 * store switches a composition root installs MFA's stores from, and the Redis
 * stores' key prefixes, which the Redis package's modules read.
 *
 * `mfa.mode` is `"off"` by reference default and admits its three values; one
 * that is none of the three is refused here, naming its key. Whether a mode
 * other than `off` is honoured is boot's to refuse (`session-requirement-missing`
 * when no requirement named `mfa` is registered), so an operator who wrote
 * `required` never believes their logins ask for a second factor.
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

describe("the MFA configuration core owns", () => {
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

	it("admits off, optional and required", () => {
		for (const mode of ["off", "optional", "required"]) {
			expect(fromReference({ MFA_MODE: mode }).mfa?.mode, mode).toBe(mode);
			expect(
				issuesAt(AppConfigSchema.safeParse({ ...makeValidAppConfig(), mfa: { mode } })),
				mode,
			).toEqual([]);
		}
	});

	it("refuses an mfa.mode that is none of the three, naming the key", () => {
		for (const mode of ["", "on", "OFF", "Required"]) {
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
			issuesAt(CoreConfigSchema.safeParse({ ...makeValidCoreConfig(), mfa: { mode: "on" } })),
		).toContain("mfa.mode");
		const err = await createApp({
			modules: [],
			bootstrapComponents: {
				config: { ...makeValidCoreConfig(), mfa: { mode: "on" } },
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

	it('reads a configuration with no mfa section, or no mode, as mode "off"', () => {
		// A hand-built composition root that never wrote the key boots with MFA
		// off: "off" is the default in the schema as well as in reference.conf.
		// The template and create-app flip their own default; core keeps its
		// (ADR 2026-09-28-session-admission).
		const { mfa: _absent, ...withoutMfa } = makeValidCoreConfig() as Record<string, unknown>;
		expect((CoreConfigSchema.parse(withoutMfa) as { mfa?: { mode?: string } }).mfa?.mode).toBe(
			"off",
		);
		expect(
			(
				CoreConfigSchema.parse({ ...withoutMfa, mfa: { transactionTtlSeconds: 600 } }) as {
					mfa?: Record<string, unknown>;
				}
			).mfa,
		).toEqual({ mode: "off", transactionTtlSeconds: 600 });
		expect(AppConfigSchema.parse(makeValidAppConfig()).mfa?.mode).toBe("off");
	});

	it("keeps the rest of the mfa section for the package that owns it", () => {
		const parsed = CoreConfigSchema.parse({
			...makeValidCoreConfig(),
			mfa: { mode: "off", transactionTtlSeconds: 600 },
		}) as { mfa?: Record<string, unknown> };
		expect(parsed.mfa).toEqual({ mode: "off", transactionTtlSeconds: 600 });
	});

	it("resolves the Redis stores' key prefixes from reference.conf, and from their environment variables", () => {
		const defaults = fromReference();
		expect(defaults.redisMfaFactorStore?.keyPrefix).toBe("mfaf:");
		expect(defaults.redisMfaTransactionStore?.keyPrefix).toBe("mfat:");
		const overridden = fromReference({
			REDIS_MFA_FACTOR_STORE_KEY_PREFIX: "tenant-a:mfaf:",
			REDIS_MFA_TRANSACTION_STORE_KEY_PREFIX: "tenant-a:mfat:",
		});
		expect(overridden.redisMfaFactorStore?.keyPrefix).toBe("tenant-a:mfaf:");
		expect(overridden.redisMfaTransactionStore?.keyPrefix).toBe("tenant-a:mfat:");
	});

	it("keeps the Redis stores' key prefixes through the strip-mode schema, for the modules that read them", () => {
		const parsed = AppConfigSchema.parse({
			...makeValidAppConfig(),
			redisMfaFactorStore: { keyPrefix: "t:mfaf:" },
			redisMfaTransactionStore: { keyPrefix: "t:mfat:" },
		});
		expect(parsed.redisMfaFactorStore).toEqual({ keyPrefix: "t:mfaf:" });
		expect(parsed.redisMfaTransactionStore).toEqual({ keyPrefix: "t:mfat:" });
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
