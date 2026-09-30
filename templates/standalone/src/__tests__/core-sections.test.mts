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
 * Core's own settings under `core {}` and the JWKS module's under `jwks {}`,
 * through the template's own reading: its layers read once under one
 * environment, phase one's switches, then the layers over every loaded
 * package's `reference.conf` handed to boot. A path they moved from, written
 * in the operator's own layer, refuses boot naming the new one;
 * `DEPLOYMENT_MODE`, renamed `CORE_DEPLOYMENT_MODE`, refuses boot unless the
 * new name carries the same value.
 */

import { BootError } from "@o3co/auth-provider-core";
import request from "supertest";
import { afterEach, describe, expect, it } from "vitest";
import {
	type ComposeOptions,
	type Composition,
	compose,
	ISSUER,
	SINGLE_ENV,
} from "./all-modules-composition.fixture.mjs";

/** The fixture's single-replica environment, with neither name of the replica count set. */
const BASE: Readonly<Record<string, string>> = Object.fromEntries(
	Object.entries(SINGLE_ENV).filter(
		([name]) => name !== "DEPLOYMENT_MODE" && name !== "CORE_DEPLOYMENT_MODE",
	),
);

let current: Composition | undefined;

afterEach(async () => {
	await current?.handle.dispose();
	current = undefined;
});

/** Boots under `env` beside `BASE`, and remembers the composition so `afterEach` disposes it. */
async function boot(env: Record<string, string>, more: ComposeOptions = {}): Promise<Composition> {
	current = await compose({ env: { ...BASE, ...env }, ...more });
	return current;
}

/** What boot refused with. */
async function refused(env: Record<string, string>, more: ComposeOptions = {}): Promise<BootError> {
	try {
		await boot(env, more);
	} catch (err) {
		if (err instanceof BootError) return err;
		throw err;
	}
	throw new Error("the composition booted");
}

describe("core's own settings and the JWKS module's, as the template reads them", () => {
	it("boots the shipped configuration: core.sessionRequirements.expected is [], the replica count what CORE_DEPLOYMENT_MODE sets", async () => {
		const composition = await boot({ CORE_DEPLOYMENT_MODE: "single" });

		const config = composition.config as unknown as Record<string, unknown>;
		expect(config.core).toMatchObject({ sessionRequirements: { expected: [] } });
		expect(config).not.toHaveProperty("sessionRequirements");
		expect(config).not.toHaveProperty("deployment");
		expect(composition.handle.components.deploymentMode).toBe("single");
	});

	it("serves the JWKS at the path JWKS_PATH sets, for the max-age JWKS_CACHE_MAX_AGE sets, and advertises it as jwks_uri", async () => {
		const composition = await boot({
			CORE_DEPLOYMENT_MODE: "single",
			JWKS_PATH: "/keys/jwks.json",
			JWKS_CACHE_MAX_AGE: "600",
		});

		const jwks = await request(composition.app).get("/keys/jwks.json");
		expect(jwks.status).toBe(200);
		expect(jwks.headers["cache-control"]).toBe("public, max-age=600");
		const discovery = await request(composition.app).get("/.well-known/openid-configuration");
		expect(discovery.body.jwks_uri).toBe(`${ISSUER}/keys/jwks.json`);
	});
});

describe("a path core's or the JWKS module's settings moved from, written in the operator's own layer", () => {
	it.each([
		[
			'deployment.mode = "single"',
			"core",
			"deployment.mode",
			"core.deployment.mode",
			"CORE_DEPLOYMENT_MODE",
		],
		[
			"sessionRequirements.expected = []",
			"core",
			"sessionRequirements.expected",
			"core.sessionRequirements.expected",
			undefined,
		],
		[
			'oauth.jwt.jwksPath = "/keys/jwks.json"',
			"jwks",
			"oauth.jwt.jwksPath",
			"jwks.path",
			"JWKS_PATH",
		],
		[
			"oauth.jwt.jwksCacheMaxAge = 60",
			"jwks",
			"oauth.jwt.jwksCacheMaxAge",
			"jwks.cacheMaxAge",
			"JWKS_CACHE_MAX_AGE",
		],
	])(
		"%s: refused, naming %s's new path and the variable that binds it, if any",
		async (hocon, module, from, to, variable) => {
			const err = await refused(
				{ CORE_DEPLOYMENT_MODE: "single" },
				{ operatorHocon: `${hocon}\n` },
			);

			expect(err.details).toEqual({
				reason: "config-path-relocated",
				relocated: [
					{
						module,
						from,
						to,
						...(variable === undefined ? {} : { environmentVariable: variable }),
					},
				],
			});
		},
	);
});

describe("DEPLOYMENT_MODE, renamed CORE_DEPLOYMENT_MODE, through the template's reading", () => {
	it("set alone: refused, naming the new variable and core.deployment.mode", async () => {
		const err = await refused({ DEPLOYMENT_MODE: "single" });

		expect(err.details).toEqual({
			reason: "environment-variable-renamed",
			renamed: [
				{
					module: "core",
					from: "DEPLOYMENT_MODE",
					to: "CORE_DEPLOYMENT_MODE",
					path: "core.deployment.mode",
					state: "unset",
				},
			],
		});
	});

	it("set beside the new name at a different value: refused, naming neither value", async () => {
		const err = await refused({
			DEPLOYMENT_MODE: "old-mode-5e2d",
			CORE_DEPLOYMENT_MODE: "new-mode-c81a",
		});

		expect(err.details).toMatchObject({
			renamed: [{ from: "DEPLOYMENT_MODE", to: "CORE_DEPLOYMENT_MODE", state: "different" }],
		});
		expect(err.message).not.toContain("old-mode-5e2d");
		expect(err.message).not.toContain("new-mode-c81a");
	});

	it("set beside the new name at the same value: boots with that mode", async () => {
		const composition = await boot({ DEPLOYMENT_MODE: "single", CORE_DEPLOYMENT_MODE: "single" });

		expect(composition.handle.components.deploymentMode).toBe("single");
	});

	it("unset, with the new name set: boots with its mode", async () => {
		const composition = await boot({ CORE_DEPLOYMENT_MODE: "single" });

		expect(composition.handle.components.deploymentMode).toBe("single");
	});
});
