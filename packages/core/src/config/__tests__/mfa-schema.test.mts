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
 * the two store switches a composition root installs MFA's stores from, and
 * the Redis stores' key prefixes, which the Redis package's modules read.
 *
 * `mfa.mode` and the step-up page, `mfa.page.url`, are not core's: they are
 * the MFA module's keys, which its package's `reference.conf` defaults. Core's
 * schema and `reference.conf` name no `mfa` section and no `endpoints.mfa`,
 * and boot passes an `mfa` section through untouched, to whichever module
 * reads it.
 */

import { fileURLToPath } from "node:url";
import { parseFile } from "@o3co/ts.hocon";
import { validate } from "@o3co/ts.hocon/zod";
import { describe, expect, it } from "vitest";
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
	it("resolves from reference.conf: both stores in memory", () => {
		const config = fromReference();
		expect(config.mfaFactorStore?.adapter).toBe("memory");
		expect(config.mfaTransactionStore?.adapter).toBe("memory");
	});

	it("reads each from its environment variable", () => {
		const config = fromReference({
			MFA_FACTOR_STORE_ADAPTER: "store",
			MFA_TRANSACTION_STORE_ADAPTER: "redis",
		});
		expect(config.mfaFactorStore?.adapter).toBe("store");
		expect(config.mfaTransactionStore?.adapter).toBe("redis");
	});

	it("names no mfa section: neither core's schema nor its reference.conf, which binds no MFA_MODE", () => {
		expect(Object.keys(CoreConfigSchema.shape)).not.toContain("mfa");
		expect(Object.keys(AppConfigSchema.shape)).not.toContain("mfa");
		const raw = parseFile(REFERENCE_CONF, { env: { ...ENV, MFA_MODE: "required" } }).toObject();
		expect(raw).not.toHaveProperty("mfa");
	});

	it("names no step-up page: neither core's schema nor its reference.conf, which binds no ENDPOINTS_MFA_URL", () => {
		expect(Object.keys(AppConfigSchema.shape.endpoints.shape)).not.toContain("mfa");
		const raw = parseFile(REFERENCE_CONF, {
			env: { ...ENV, ENDPOINTS_MFA_URL: "/account/mfa" },
		}).toObject() as { endpoints?: object };
		expect(raw.endpoints).not.toHaveProperty("mfa");
	});

	it("boots a configuration whatever its mfa section holds, handing the section on as written", async () => {
		const handle = await createApp({
			modules: [],
			bootstrapComponents: {
				config: { ...makeValidCoreConfig(), mfa: { mode: "sometimes", lockout: {} } },
				pathResolver: (p: string) => p,
			} as never,
		});
		expect((handle.components.config as { mfa?: unknown } | undefined)?.mfa).toEqual({
			mode: "sometimes",
			lockout: {},
		});
		await handle.dispose();
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
