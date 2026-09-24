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
 * The three budgets a limiter module seeds from their own config keys, through
 * `createApp` with the bundled memory limiter module in the `rateLimiter`
 * slot — what a composition actually runs.
 *
 * Absent — the section or the key not given, a module not loaded — seeds
 * nothing, and the prefix runs on the adapter's default, as #270 and #448
 * intend. Present but not a spec a limiter can apply is a configuration
 * someone wrote: it used to be skipped as silently, so the route ran on the
 * adapter's 60 per 60 s instead of what was written. It must refuse to boot,
 * naming the config key, not the limiter.
 */

import express, { Router } from "express";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { createApp } from "#/index.mjs";
import { defineModule } from "#/modules/manifest/index.mjs";
import { memoryRateLimiterModule } from "#/ratelimit/module.mjs";
import type { RateLimiter } from "#/ratelimit/types.mjs";
import { makeValidAppConfig } from "#/testing/fixtures/valid-config.mjs";

/** A route that asks the wired limiter which limit a prefix gets. */
const probeModule = defineModule({
	name: "test:seeded-spec-probe",
	requires: ["rateLimiter"] as const,
	contributes: {
		routes: [
			(deps: unknown) => {
				const { rateLimiter } = deps as { rateLimiter: RateLimiter };
				const router = Router();
				router.get("/probe/:prefix", async (req, res) => {
					const decision = await rateLimiter.check(`${req.params.prefix}:ip:192.0.2.1`, {
						ip: "192.0.2.1",
					});
					res.json({ limit: decision.limit });
				});
				return { id: "seeded-spec-probe", mountPath: "/", handler: router as never };
			},
		],
	},
});

type Config = Record<string, unknown> & { rateLimit: Record<string, unknown> };

const baseConfig = (): Config => {
	const config = makeValidAppConfig() as unknown as Config;
	config.memoryRateLimiter = {
		limits: {},
		defaultLimit: { limit: 60, windowSeconds: 60 },
		maxBuckets: 10_000,
	};
	return config;
};

const boot = async (config: Config) => {
	const handle = await createApp({
		modules: [memoryRateLimiterModule, probeModule],
		bootstrapComponents: { config: config as never, pathResolver: (s: string) => s } as never,
	});
	const app = express();
	app.use(handle.router);
	return { app, handle };
};

/** The boot's refusal, with every cause it carries, as one text. */
const refusal = async (config: Config): Promise<string> => {
	try {
		const { handle } = await boot(config);
		await handle.dispose();
	} catch (err) {
		const texts: string[] = [];
		let at: unknown = err;
		while (at instanceof Error) {
			texts.push(at.message);
			at = at.cause;
		}
		return texts.join("\n");
	}
	return "booted";
};

const limitOf = async (config: Config, prefix: string): Promise<number | undefined> => {
	const { app, handle } = await boot(config);
	try {
		return (await request(app).get(`/probe/${prefix}`)).body.limit;
	} finally {
		await handle.dispose();
	}
};

describe("a seeded budget whose key is absent", () => {
	it("seeds nothing, and the prefix runs on the adapter's default", async () => {
		const config = baseConfig();
		config.rateLimit = { failMode: "open" };
		expect(await limitOf(config, "login")).toBe(60);
		expect(await limitOf(baseConfig(), "device_verification")).toBe(60);
		expect(await limitOf(baseConfig(), "webauthn-authentication-options")).toBe(60);
	});
});

describe("a seeded budget given as the strings HOCON substitutes", () => {
	// An environment variable reaches the config as a string, and every
	// schema that owns these keys coerces it. createApp parses neither the
	// `rateLimit` nor the `webauthn` section, so a composition that hands it
	// HOCON directly must boot on the budget written, not refuse it.
	it("boots on rateLimit.login as numeric strings, and applies it", async () => {
		const config = baseConfig();
		config.rateLimit = { ...config.rateLimit, login: { windowMs: "900000", limit: "20" } };
		expect(await limitOf(config, "login")).toBe(20);
	});

	it("boots on webauthn.rateLimit.authenticationOptions as numeric strings, and applies it", async () => {
		const config = baseConfig();
		config.webauthn = {
			rateLimit: { authenticationOptions: { limit: "30", windowSeconds: "60" } },
		};
		expect(await limitOf(config, "webauthn-authentication-options")).toBe(30);
	});
});

describe("a seeded budget whose key is present but not a spec a limiter can apply", () => {
	it("refuses to boot on rateLimit.login, naming it and not the limiter", async () => {
		for (const login of [
			{ windowMs: 900_000, limit: 0 },
			{ windowMs: 0, limit: 20 },
			{ windowMs: 900_000, limit: "twenty" },
			{ windowMs: 900_000, limit: "   " },
			{ windowMs: 1e19, limit: 20 },
			null,
		]) {
			const config = baseConfig();
			config.rateLimit = { ...config.rateLimit, login };
			const text = await refusal(config);
			expect(text, JSON.stringify(login)).toMatch(/rateLimit\.login must be/);
			expect(text, JSON.stringify(login)).not.toMatch(/createMemoryRateLimiter|limits\.login/);
		}
	});

	it("refuses oauth.deviceAuthorization.rateLimit before any seed: createApp validates the oauth section", async () => {
		// Unlike `rateLimit` and `webauthn`, this key sits in the section
		// CoreConfigSchema parses, so through createApp the schema refuses it
		// first, by path. The seed's own refusal is for a limiter module used
		// outside createApp; the module tests pin it.
		for (const rateLimit of [
			{ limit: 5, windowSeconds: 0 },
			{ limit: 5, windowSeconds: 1e13 },
		]) {
			const config = baseConfig();
			const oauth = config.oauth as Record<string, unknown>;
			config.oauth = { ...oauth, deviceAuthorization: { rateLimit } };
			const err = await boot(config).then(
				() => undefined,
				(caught: unknown) => caught,
			);
			const issues = (err as { details?: { issues?: { path: unknown[] }[] } }).details?.issues;
			expect(
				issues?.map((issue) => issue.path.join(".")),
				JSON.stringify(rateLimit),
			).toContain("oauth.deviceAuthorization.rateLimit.windowSeconds");
		}
	});

	it("refuses to boot on webauthn.rateLimit.authenticationOptions, naming it and not the limiter", async () => {
		for (const authenticationOptions of [
			{ limit: 30, windowSeconds: 0 },
			{ limit: 1.5, windowSeconds: 60 },
			{ limit: "thirty", windowSeconds: 60 },
			{ limit: "", windowSeconds: 60 },
			{ limit: 30, windowSeconds: 1e13 },
		]) {
			const config = baseConfig();
			config.webauthn = { rateLimit: { authenticationOptions } };
			const text = await refusal(config);
			expect(text, JSON.stringify(authenticationOptions)).toMatch(
				/webauthn\.rateLimit\.authenticationOptions must be/,
			);
			expect(text, JSON.stringify(authenticationOptions)).not.toMatch(
				/createMemoryRateLimiter|limits\.webauthn/,
			);
		}
	});
});
