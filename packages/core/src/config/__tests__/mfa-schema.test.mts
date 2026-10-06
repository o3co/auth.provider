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
 * Core owns none of the MFA configuration (ADR
 * 2026-09-25-multi-factor-authentication): which modules provide MFA's stores
 * is a composition root's choice, and the Redis stores' key prefixes are the
 * Redis package's modules' sections. `mfaFactorStore` and
 * `mfaTransactionStore`, where the selections were, are presence-only.
 *
 * `mfa.mode` and the step-up page, `mfa.page.url`, are not core's: they are
 * the MFA module's keys, which its package's `reference.conf` defaults. Core's
 * schema and `reference.conf` name no `mfa` section and no `endpoints.mfa`,
 * and boot passes an `mfa` section through untouched, to whichever module
 * reads it.
 */

import { fileURLToPath } from "node:url";
import { parseFile } from "@o3co/ts.hocon";
import { describe, expect, it } from "vitest";
import { CoreConfigSchema } from "#/config/application.schema.mjs";
import { createApp } from "#/index.mjs";
import { makeValidCoreConfig } from "#/testing/fixtures/valid-config.mjs";

const REFERENCE_CONF = fileURLToPath(new URL("../../../config/reference.conf", import.meta.url));

const ENV = {
	OAUTH_JWT_SECRET: "mfa-schema-test.at-least-32-bytes.ok",
	OAUTH_JWT_ISSUER: "https://auth.test",
};

/** What core's reference.conf resolves to under `env`, as written. */
const fromReference = (env: Record<string, string> = {}): Record<string, unknown> =>
	parseFile(REFERENCE_CONF, { env: { ...ENV, ...env } }).toObject() as Record<string, unknown>;

/** The config slot of a boot with no module, handed `extra` beside core's sections. */
async function bootedConfig(extra: Record<string, unknown>): Promise<Record<string, unknown>> {
	const handle = await createApp({
		modules: [],
		bootstrapComponents: {
			config: { ...makeValidCoreConfig(), ...extra },
			pathResolver: (p: string) => p,
		} as never,
	});
	const config = handle.components.config as unknown as Record<string, unknown>;
	await handle.dispose();
	return config;
}

describe("the MFA configuration core owns", () => {
	it("ships no store selection: its reference.conf binds neither old variable", () => {
		const config = fromReference({
			MFA_FACTOR_STORE_ADAPTER: "store",
			MFA_TRANSACTION_STORE_ADAPTER: "redis",
		});
		expect(config).not.toHaveProperty("mfaFactorStore");
		expect(config).not.toHaveProperty("mfaTransactionStore");
	});

	it("names no mfa section: neither core's schema nor its reference.conf, which binds no MFA_MODE", () => {
		expect(Object.keys(CoreConfigSchema.shape)).not.toContain("mfa");
		const raw = parseFile(REFERENCE_CONF, { env: { ...ENV, MFA_MODE: "required" } }).toObject();
		expect(raw).not.toHaveProperty("mfa");
	});

	it("names no step-up page: core's schema declares no endpoints, and its reference.conf, which binds no ENDPOINTS_MFA_URL, has no endpoints", () => {
		expect(Object.keys(CoreConfigSchema.shape)).not.toContain("endpoints");
		const raw = parseFile(REFERENCE_CONF, {
			env: { ...ENV, ENDPOINTS_MFA_URL: "/account/mfa" },
		}).toObject();
		expect(raw).not.toHaveProperty("endpoints");
	});

	it("boots a configuration whatever its mfa section holds, handing the section on as written", async () => {
		const config = await bootedConfig({ mfa: { mode: "sometimes", lockout: {} } });
		expect(config.mfa).toEqual({ mode: "sometimes", lockout: {} });
	});

	it("ships no Redis store's key prefix: each is the Redis package's", () => {
		const defaults = fromReference();
		for (const section of [
			"redisMfaFactorStore",
			"redisMfaTransactionStore",
			"redis-mfa-factor-store",
			"redis-mfa-transaction-store",
		]) {
			expect(defaults, section).not.toHaveProperty(section);
		}
	});

	it("boots with the Redis stores' sections, and the paths they moved from, handing them on as written", async () => {
		const written = {
			"redis-mfa-factor-store": { keyPrefix: "t:mfaf:" },
			"redis-mfa-transaction-store": { keyPrefix: "t:mfat:" },
			redisMfaFactorStore: { keyPrefix: "t:old-mfaf:" },
			redisMfaTransactionStore: { keyPrefix: "t:old-mfat:" },
		};
		expect(await bootedConfig(written)).toMatchObject(written);
	});

	it("boots with where the selections were, whatever they hold, handing them on as written: core reads nothing of them", async () => {
		const written = {
			mfaFactorStore: { adapter: "sql" },
			mfaTransactionStore: { adapter: "store" },
		};
		expect(await bootedConfig(written)).toMatchObject(written);
	});
});
