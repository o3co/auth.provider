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
 * `oauth {}` where no loaded module's section is `oauth`: core reads a few of
 * its keys by path — the issuer, the token lifetimes, the revocation modes two
 * absence policies are keyed in — and refuses every other key the
 * configuration sets there (`config-validation-failed`, one issue per path,
 * telling the operator to load oauthEndpointsModule, never the value), so
 * a retired key, a misspelt one or one only that module reads is not accepted unread. A
 * configured issuer that is not canonical is refused the same way. Where the
 * module is loaded, its own section refuses, and this check does not run (the
 * oauth package's `sections.test.mts`).
 */

import { describe, expect, it } from "vitest";
import { createApp } from "#/boot/create-app.mjs";
import { BootError } from "#/boot/types.mjs";
import { makeValidCoreConfig } from "#/testing/fixtures/valid-config.mjs";

/** Core's valid configuration with `oauth` as given, and none of the oauth package's other sections. */
const withOAuth = (oauth: unknown): Record<string, unknown> => {
	const {
		oauth: _oauth,
		"oauth-session": _session,
		"oauth-authorization": _authorization,
		...rest
	} = makeValidCoreConfig() as Record<string, unknown>;
	return { ...rest, oauth };
};

const boot = (config: Record<string, unknown>) =>
	createApp({
		modules: [],
		bootstrapComponents: { config, pathResolver: (p: string) => p } as never,
	});

const refusal = async (config: Record<string, unknown>): Promise<BootError> => {
	const caught = await boot(config).then(
		async (handle) => {
			await handle.dispose();
			return undefined;
		},
		(err: unknown) => err,
	);
	expect(caught).toBeInstanceOf(BootError);
	return caught as BootError;
};

const pathsOf = (err: BootError): string[] =>
	(err.details as unknown as { issues: { path: PropertyKey[] }[] }).issues.map((issue) =>
		issue.path.map(String).join("."),
	);

/** What core reads, as the oauth package's reference sets it under an environment. */
const READ = {
	jwt: { issuer: "https://auth.test" },
	accessToken: { defaultExpiresIn: 600, maxExpiresIn: 900 },
	refreshToken: { expiresIn: 86400 },
	revocation: { accessToken: "unsupported", subject: "unsupported" },
};

describe("oauth {} with no loaded module whose section it is", () => {
	it("boots with every key core reads, and nothing else", async () => {
		const handle = await boot(withOAuth(READ));
		await handle.dispose();
	});

	it("boots with no oauth {}, an empty one, and keys whose value is undefined", async () => {
		for (const config of [
			withOAuth(undefined),
			withOAuth({}),
			withOAuth({ jwt: {}, revocation: {} }),
			withOAuth({ ...READ, oidcMode: undefined }),
		]) {
			const handle = await boot(config);
			await handle.dispose();
		}
	});

	it.each([
		[
			"a retired key, authorize.allowUnmarkedClients",
			{ authorize: { allowUnmarkedClients: false } },
			"oauth.authorize.allowUnmarkedClients",
		],
		[
			"a retired key, refreshToken.legacyTokenCompat",
			{ refreshToken: { expiresIn: 86400, legacyTokenCompat: true } },
			"oauth.refreshToken.legacyTokenCompat",
		],
		[
			"a retired flat key field, jwt.algorithm",
			{ jwt: { issuer: "https://auth.test", algorithm: "HS256" } },
			"oauth.jwt.algorithm",
		],
		["a typo", { accessToken: { defaultExpiresIm: 600 } }, "oauth.accessToken.defaultExpiresIm"],
		[
			"an unknown nested key",
			{ revocation: { accessToken: "denylist", sessions: { mode: "x" } } },
			"oauth.revocation.sessions.mode",
		],
		["a key only the oauth endpoints module reads", { oidcMode: "dual" }, "oauth.oidcMode"],
		[
			"a key the oauth endpoints module declares moved, accessToken.expiresIn",
			{ accessToken: { defaultExpiresIn: 600, expiresIn: 3600 } },
			"oauth.accessToken.expiresIn",
		],
	])("refuses %s, naming the path and the module, never the value", async (_, oauth, path) => {
		const err = await refusal(withOAuth(oauth));
		expect(err.reason).toBe("config-validation-failed");
		expect(err.stage).toBe("validateManifests");
		expect(pathsOf(err)).toEqual([path]);
		expect(err.message).toContain(`${path}: `);
		expect(err.message).toMatch(/load oauthEndpointsModule/);
		expect(err.message).not.toMatch(/HS256|"dual"|"x"/);
	});

	it("refuses every such key in one boot", async () => {
		const err = await refusal(
			withOAuth({ ...READ, oidcMode: "dual", nonce: { maxLength: 128 }, grants: { x: 1 } }),
		);
		expect(pathsOf(err).sort()).toEqual([
			"oauth.grants.x",
			"oauth.nonce.maxLength",
			"oauth.oidcMode",
		]);
	});

	it("refuses an oauth that is not a section", async () => {
		const err = await refusal(withOAuth("on"));
		expect(pathsOf(err)).toEqual(["oauth"]);
	});

	it.each(["https://auth.test/", "http://auth.test", "https://auth.test?x=1", "", 42, null])(
		"refuses the configured issuer %j: not canonical, named by its key and never its value",
		async (issuer) => {
			const err = await refusal(withOAuth({ ...READ, jwt: { issuer } }));
			expect(err.reason).toBe("config-validation-failed");
			expect(pathsOf(err)).toEqual(["oauth.jwt.issuer"]);
			expect(err.message).toMatch(/oauth\.jwt\.issuer: oauth\.jwt\.issuer must/);
			if (typeof issuer === "string" && issuer !== "") expect(err.message).not.toContain(issuer);
		},
	);
});

describe("what core reads of oauth {} without its module, by its segments, and the issuer by its value", () => {
	const issuePathsOf = (err: BootError): PropertyKey[][] =>
		(err.details as unknown as { issues: { path: PropertyKey[] }[] }).issues.map((issue) => [
			...issue.path,
		]);

	it.each([
		["an empty object", {}],
		["a list holding an empty object", [{}]],
		["an object whose only key is undefined", { nested: undefined }],
	])("refuses an issuer that is %s, which sets no leaf, at the key", async (_, issuer) => {
		const err = await refusal(withOAuth({ ...READ, jwt: { issuer } }));
		expect(err.reason).toBe("config-validation-failed");
		expect(issuePathsOf(err)).toEqual([["oauth", "jwt", "issuer"]]);
	});

	it.each([
		["a list holding an empty object", [{}]],
		["a list", ["x"]],
		["null", null],
		["a number", 1],
	])("refuses an oauth that is %s, as no section", async (_, oauth) => {
		const err = await refusal(withOAuth(oauth));
		expect(issuePathsOf(err)).toEqual([["oauth"]]);
	});

	it.each([
		["jwt.issuer", "https://auth.test"],
		["accessToken.defaultExpiresIn", 3600],
		["revocation.subject", "unsupported"],
	])(
		"refuses the literal key %j, which no dotted path it spells makes one core reads",
		async (key, value) => {
			const err = await refusal(withOAuth({ ...READ, [key]: value }));
			expect(issuePathsOf(err)).toEqual([["oauth", key]]);
		},
	);

	it("names a reserved key under oauth once", async () => {
		const err = await refusal(withOAuth({ ...READ, prototype: 1 }));
		expect(issuePathsOf(err)).toEqual([["oauth", "prototype"]]);
	});
});
