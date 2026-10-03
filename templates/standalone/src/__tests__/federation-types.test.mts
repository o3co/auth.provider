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
 * The federations the template ships are handled by the modules of their
 * types. The template loads the federation types it bundles, `google` and
 * `oidc`, whatever the configuration enables, and core dispatches each
 * enabled `core.federations` entry to the module of its `type`, under the
 * entry's name: two entries of one type are two federations. The template
 * reads no entry before boot, so a malformed one is core's to refuse, at its
 * path.
 */

import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import request from "supertest";
import { afterEach, describe, expect, it } from "vitest";
import { buildModules } from "#/buildModules.mjs";
import {
	readOwnLayers,
	readSwitches,
	resolveConfigPaths,
	resolveLayers,
	type Switches,
} from "#/configPath.mjs";
import {
	type Composition,
	compose,
	ISSUER,
	ownFiles,
	resolveConfig,
	SINGLE_ENV,
} from "./all-modules-composition.fixture.mjs";

const configDir = fileURLToPath(new URL("../../config", import.meta.url));

/** Google's authorization endpoint, where a Google federation's start sends the browser. */
const GOOGLE_AUTHORIZE = "https://accounts.google.com/o/oauth2/v2/auth";

let current: Composition | undefined;

afterEach(async () => {
	await current?.handle.dispose();
	current = undefined;
});

/** Boots and remembers the composition, so `afterEach` disposes it. */
async function boot(options: Parameters<typeof compose>[0] = {}): Promise<Composition> {
	current = await compose(options);
	return current;
}

/** What `compose` refuses under `options`. */
async function refusal(options: Parameters<typeof compose>[0]): Promise<{
	readonly reason?: string;
	readonly message: string;
}> {
	try {
		current = await compose(options);
	} catch (err) {
		return err as { reason?: string; message: string };
	}
	throw new Error("the composition booted");
}

/** `text` in a file of its own, for a layer above the composition's files. */
function hoconFile(text: string): string {
	const file = join(mkdtempSync(join(tmpdir(), "federation-types-")), "operator.conf");
	writeFileSync(file, text);
	return file;
}

/** The module names `buildModules` lists for `env`, federation ones only. */
const federationModules = (env: Readonly<Record<string, string>>): string[] =>
	buildModules(resolveConfig(env))
		.map((module) => module.name)
		.filter((name) => name.startsWith("federation-") && !name.startsWith("federation-grant"));

/** Where the start of federation `name` sends the browser. */
async function startOf(composed: Composition, name: string): Promise<URL> {
	const res = await request(composed.app).get(`/session/oauth/federation/${name}`);
	expect(res.status).toBe(302);
	return new URL(res.headers.location as string);
}

describe("the federation types the template bundles", () => {
	it("are listed whatever the configuration enables", () => {
		const off = {
			...SINGLE_ENV,
			CORE_FEDERATIONS_GOOGLE_ENABLED: "false",
			CORE_FEDERATIONS_OIDC_ENABLED: "false",
		};
		expect(federationModules(off)).toEqual(["federation-google-type", "federation-oidc"]);
		expect(federationModules(SINGLE_ENV)).toEqual(["federation-google-type", "federation-oidc"]);
	});

	it("handle every entry the template ships, each of which names its type", () => {
		const { applicationConfPath } = resolveConfigPaths(configDir, "production");
		const resolved = resolveLayers(readOwnLayers([applicationConfPath], { env: {} }), []) as {
			core?: { federations?: Record<string, { type?: unknown }> };
		};
		const types = Object.fromEntries(
			Object.entries(resolved.core?.federations ?? {}).map(([name, entry]) => [name, entry.type]),
		);
		expect(types).toEqual({ google: "google", oidc: "oidc" });
	});

	it("boot the shipped Google federation, enabled, as the provider named google that its type built", async () => {
		const composed = await boot();
		const names = composed.modules.map((module) => module.name);
		expect(names).toContain("federation-google-type");
		expect(names).not.toContain("federation-google");
		expect(composed.handle.components.federationProviders?.get("google")?.name).toBe("google");

		const start = await startOf(composed, "google");
		expect(`${start.origin}${start.pathname}`).toBe(GOOGLE_AUTHORIZE);
		expect(start.searchParams.get("client_id")).toBe(SINGLE_ENV.CORE_FEDERATIONS_GOOGLE_CLIENT_ID);
		expect(start.searchParams.get("redirect_uri")).toBe(
			"http://localhost:3000/session/oauth/federation/google/callback",
		);
	});

	it("boot a second entry of type google, under its own name, beside the shipped one", async () => {
		const callbackURL = `${ISSUER}/session/oauth/federation/google-work/callback`;
		const composed = await boot({
			operatorHocon: `core.federations.google-work {
  enabled = true
  type = "google"
  clientId = "google-work-client"
  clientSecret = "google-work-secret"
  callbackURL = ${JSON.stringify(callbackURL)}
}
`,
		});
		const providers = composed.handle.components.federationProviders;
		expect([...(providers?.keys() ?? [])].sort()).toEqual(["google", "google-work", "oidc"]);
		expect(providers?.get("google-work")?.name).toBe("google-work");

		const work = await startOf(composed, "google-work");
		expect(`${work.origin}${work.pathname}`).toBe(GOOGLE_AUTHORIZE);
		expect(work.searchParams.get("client_id")).toBe("google-work-client");
		expect(work.searchParams.get("redirect_uri")).toBe(callbackURL);
		const shipped = await startOf(composed, "google");
		expect(shipped.searchParams.get("client_id")).toBe(
			SINGLE_ENV.CORE_FEDERATIONS_GOOGLE_CLIENT_ID,
		);
	});

	it("hand an entry to the type it names, not the type its name reads as", async () => {
		// `google` of type `oidc` is a generic OIDC federation named google.
		const composed = await boot({
			operatorHocon: `core.federations.google { type = "oidc", issuer = ${JSON.stringify(SINGLE_ENV.CORE_FEDERATIONS_OIDC_ISSUER)} }\n`,
		});
		const start = await startOf(composed, "google");
		expect(start.origin).toBe(SINGLE_ENV.CORE_FEDERATIONS_OIDC_ISSUER);
		expect(start.searchParams.get("client_id")).toBe(SINGLE_ENV.CORE_FEDERATIONS_GOOGLE_CLIENT_ID);
	});

	it("refuse to guess an enabled entry's type: one that names none is refused, naming the type to set", async () => {
		// A scaffold's own `core.federations.google` entry that names no type.
		const withoutType = (config: Switches): Switches => {
			const core = (config as { core?: { federations?: Record<string, object> } }).core;
			const { type: _dropped, ...google } = (core?.federations?.google ?? {}) as {
				type?: unknown;
			};
			return {
				...config,
				core: { ...core, federations: { ...core?.federations, google } },
			} as unknown as Switches;
		};
		const err = await refusal({ config: withoutType });
		expect(err.reason).toBe("federation-type-unhandled");
		expect(err.message).toContain('set core.federations.google.type = "google"');
	});
});

describe("the template reads no federation entry before boot", () => {
	it("passes a malformed entry through phase one, and boot refuses it at its path", async () => {
		const operatorHocon = 'core.federations.okta { enabled = "maybe", type = "oidc" }\n';
		expect(() =>
			readSwitches(readOwnLayers([hoconFile(operatorHocon), ...ownFiles()], { env: SINGLE_ENV })),
		).not.toThrow();
		const err = await refusal({ operatorHocon });
		expect(err.reason).toBe("config-validation-failed");
		expect(err.message).toContain("core.federations.okta.enabled");
	});

	it.each([
		["accessType", '"sometimes"'],
		// A bare string where a list belongs: the natural typo.
		["redirectAllowlist", '"https://app.test/home"'],
		["sessionDomain", "42"],
		["requireAuthorizationResponseIss", '"no"'],
		// Only an environment variable's string is read as a flag's spelling.
		["requireAuthorizationResponseIss", "1"],
		["requireAuthorizationResponseIss", "[true]"],
	])(
		"leaves %s, a key of the entry's type, to the type's schema, which core refuses it by, at its path",
		async (key, value) => {
			const err = await refusal({ operatorHocon: `core.federations.google.${key} = ${value}\n` });
			expect(err.reason).toBe("config-validation-failed");
			expect(err.message).toContain(`core.federations.google.${key}`);
		},
	);
});

describe("an enabled Google federation's credentials", () => {
	it.each([
		["unset", undefined],
		["exported empty", ""],
	])(
		"refuse the boot when the client secret is %s, at its path, quoting no value of the entry",
		async (_case, secret) => {
			const { CORE_FEDERATIONS_GOOGLE_CLIENT_SECRET: _shipped, ...env } = SINGLE_ENV;
			const err = await refusal({
				env: secret === undefined ? env : { ...env, CORE_FEDERATIONS_GOOGLE_CLIENT_SECRET: secret },
			});
			expect(err.reason).toBe("config-validation-failed");
			expect(err.message).toContain("core.federations.google.clientSecret");
			expect(err.message).not.toContain(SINGLE_ENV.CORE_FEDERATIONS_GOOGLE_CLIENT_ID as string);
		},
	);
});
