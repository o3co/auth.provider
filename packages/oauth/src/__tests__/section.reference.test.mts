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
 * The defaults of `oauth {}` and the environment variables bound to its keys
 * live in this package's `config/reference.conf`, read by the module's schema.
 * Core's `reference.conf` still sets most of the same paths, to the same values
 * and with the same variables, until core stops declaring `oauth {}`: every
 * path it sets is held equal here, so the order a composition layers them in
 * decides nothing. Core's alone keeps the tombstone of a key it retired, and
 * this package's alone sets the refresh-token family policy keys.
 */

import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { resolveAccessTokenLifetime } from "@o3co/auth-provider-core";
import { parseFile, parseString } from "@o3co/ts.hocon";
import { describe, expect, it } from "vitest";
import { oauthSectionSchema } from "#/section.mjs";

const REFERENCE = fileURLToPath(new URL("../../config/reference.conf", import.meta.url));
const CORE_REFERENCE = createRequire(import.meta.url).resolve(
	"@o3co/auth-provider-core/reference.conf",
);

const MARKER = "__OAUTH_SECTION_MARKER__";

function markedPaths(tree: unknown, prefix = ""): string[] {
	if (typeof tree === "object" && tree !== null && !Array.isArray(tree)) {
		return Object.entries(tree).flatMap(([key, value]) =>
			markedPaths(value, prefix === "" ? key : `${prefix}.${key}`),
		);
	}
	return tree === MARKER ? [prefix] : [];
}

/** Every `<VAR> at <path>` a file binds under `oauth {}`, each variable resolved alone. */
function oauthBindings(file: string): string[] {
	const variables = [
		...new Set(
			[...readFileSync(file, "utf8").matchAll(/\$\{\??([A-Za-z0-9_]+)\}/g)].map((match) =>
				String(match[1]),
			),
		),
	];
	return variables
		.flatMap((variable) =>
			markedPaths(parseFile(file, { env: { [variable]: MARKER } }).toObject()).map(
				(path) => `${variable} at ${path}`,
			),
		)
		.filter((binding) => / at oauth\./.test(binding))
		.sort();
}

const oauthOf = (file: string, env: Record<string, string> = {}): Record<string, unknown> =>
	(parseFile(file, { env }).toObject() as { oauth: Record<string, unknown> }).oauth;

const isSection = (value: unknown): value is Record<string, unknown> =>
	typeof value === "object" &&
	value !== null &&
	!Array.isArray(value) &&
	Object.keys(value).length > 0;

/** Every leaf of `tree` as `[path, value]`; an empty table is a leaf. */
function leavesOf(tree: Record<string, unknown>, prefix = ""): [string, unknown][] {
	return Object.entries(tree).flatMap(([key, value]): [string, unknown][] => {
		const path = prefix === "" ? key : `${prefix}.${key}`;
		return isSection(value) ? leavesOf(value, path) : [[path, value]];
	});
}

/** The value at a dotted `path` of `tree`, or `undefined`. */
const valueAt = (tree: unknown, path: string): unknown =>
	path.split(".").reduce<unknown>((node, key) => (isSection(node) ? node[key] : undefined), tree);

describe("the package's reference binds every variable of oauth {} at its path", () => {
	it.each([
		["OAUTH_JWT_ISSUER", "oauth.jwt.issuer"],
		["OAUTH_JWT_LEGACY_TYP_ACCEPT", "oauth.jwt.legacyTypAccept"],
		["OAUTH_ACCESS_TOKEN_DEFAULT_EXPIRES_IN", "oauth.accessToken.defaultExpiresIn"],
		["OAUTH_ACCESS_TOKEN_MAX_EXPIRES_IN", "oauth.accessToken.maxExpiresIn"],
		["OAUTH_ACCESS_TOKEN_EXPIRES_IN", "oauth.accessToken.expiresIn"],
		["OAUTH_REFRESH_TOKEN_EXPIRES_IN", "oauth.refreshToken.expiresIn"],
		["OAUTH_REFRESH_TOKEN_UNKNOWN_FAMILY_POLICY", "oauth.refreshToken.unknownFamilyPolicy"],
		["OAUTH_OIDC_MODE", "oauth.oidcMode"],
		["OAUTH_REVOCATION_ACCESS_TOKEN", "oauth.revocation.accessToken"],
		["OAUTH_REVOCATION_SUBJECT", "oauth.revocation.subject"],
		["OAUTH_REQUIRE_EMAIL_VERIFIED", "oauth.requireEmailVerified"],
		["OAUTH_REQUIRE_GRANT_TYPE_ALLOWLIST", "oauth.requireGrantTypeAllowlist"],
		["OAUTH_NONCE_MAX_LENGTH", "oauth.nonce.maxLength"],
		["OAUTH_RESOURCE_INDICATOR_ENABLED", "oauth.resourceIndicator.enabled"],
	])("binds %s at %s", (variable, path) => {
		expect(
			oauthBindings(REFERENCE).filter((binding) => binding.startsWith(`${variable} `)),
		).toEqual([`${variable} at ${path}`]);
	});

	it("binds every variable core's reference binds under oauth {}, at the same path, but core's tombstone", () => {
		// Core keeps the substitution that routes a still-exported variable of a
		// key it retired into its removed-key refusal.
		const tombstone =
			"OAUTH_AUTHORIZE_ALLOW_UNMARKED_CLIENTS at oauth.authorize.allowUnmarkedClients";
		const core = oauthBindings(CORE_REFERENCE);
		expect(core).toContain(tombstone);
		expect(core.length).toBeGreaterThanOrEqual(14);
		expect(oauthBindings(REFERENCE)).toEqual(
			expect.arrayContaining(core.filter((binding) => binding !== tombstone)),
		);
		expect(oauthBindings(REFERENCE)).not.toContain(tombstone);
	});

	it("sets every default core's reference sets under oauth {}, leaf by leaf, to the same value", () => {
		for (const env of [{}, { OAUTH_JWT_ISSUER: "https://auth.test" }] as Record<string, string>[]) {
			const core = leavesOf(oauthOf(CORE_REFERENCE, env));
			const own = oauthOf(REFERENCE, env);
			expect(core.length).toBeGreaterThan(0);
			expect(Object.fromEntries(core.map(([path]) => [path, valueAt(own, path)]))).toEqual(
				Object.fromEntries(core),
			);
		}
	});

	it("sets nothing under oauth {} core's does not, but the consent page and the Client ID Metadata Documents", () => {
		const core = Object.keys(oauthOf(CORE_REFERENCE));
		expect(
			Object.keys(oauthOf(REFERENCE))
				.filter((key) => !core.includes(key))
				.sort(),
		).toEqual(["clientIdMetadataDocuments", "consentPage"]);
	});
});

describe("the reference, read by the module's schema", () => {
	const ISSUER = { OAUTH_JWT_ISSUER: "https://auth.test" };

	/** `oauth {}` as the module parses it: the reference under `env`, below `applicationConf`. */
	function load(env: Record<string, string> = {}, applicationConf?: string) {
		const reference = parseFile(REFERENCE, { env: { ...ISSUER, ...env } });
		const layered =
			applicationConf === undefined
				? reference
				: parseString(applicationConf, { env: { ...ISSUER, ...env } }).withFallback(reference);
		return oauthSectionSchema.parse((layered.toObject() as { oauth: unknown }).oauth);
	}

	it("parses with no variable but the issuer set, every switch off and the shipped defaults", () => {
		expect(load()).toEqual({
			jwt: { issuer: "https://auth.test", legacyTypAccept: false },
			accessToken: { expiresIn: 3600 },
			refreshToken: { expiresIn: 86400, unknownFamilyPolicy: "reject", legacyRtPolicy: "reject" },
			oidcMode: "oidc-required",
			requireEmailVerified: false,
			requireGrantTypeAllowlist: false,
			authorize: { acrValues: {} },
			nonce: { maxLength: 256 },
			resourceIndicator: { enabled: false },
			revocation: { accessToken: "denylist" },
			consentPage: { url: "/consent" },
			clientIdMetadataDocuments: expect.objectContaining({ enabled: false }),
		});
	});

	it("refuses the reference without an issuer: there is no default", () => {
		expect(() => oauthSectionSchema.parse(oauthOf(REFERENCE))).toThrow(/issuer/);
	});

	it("reads each variable as the string it carries", () => {
		expect(
			load({
				OAUTH_JWT_LEGACY_TYP_ACCEPT: "true",
				OAUTH_REFRESH_TOKEN_EXPIRES_IN: "7200",
				OAUTH_REFRESH_TOKEN_UNKNOWN_FAMILY_POLICY: "accept",
				OAUTH_OIDC_MODE: "dual",
				OAUTH_REVOCATION_ACCESS_TOKEN: "unsupported",
				OAUTH_REVOCATION_SUBJECT: "watermark",
				OAUTH_REQUIRE_EMAIL_VERIFIED: "1",
				OAUTH_REQUIRE_GRANT_TYPE_ALLOWLIST: "TRUE",
				OAUTH_NONCE_MAX_LENGTH: "64",
				OAUTH_RESOURCE_INDICATOR_ENABLED: "true",
			}),
		).toMatchObject({
			jwt: { legacyTypAccept: true },
			refreshToken: { expiresIn: 7200, unknownFamilyPolicy: "accept" },
			oidcMode: "dual",
			revocation: { accessToken: "unsupported", subject: "watermark" },
			requireEmailVerified: true,
			requireGrantTypeAllowlist: true,
			nonce: { maxLength: 64 },
			resourceIndicator: { enabled: true },
		});
	});

	describe("the access-token lifetime", () => {
		const lifetime = (env: Record<string, string> = {}, applicationConf?: string) =>
			resolveAccessTokenLifetime({ oauth: load(env, applicationConf) });

		it("ships a one-hour default and no extension past it", () => {
			expect(lifetime()).toEqual({ defaultExpiresIn: 3600, maxExpiresIn: 3600 });
			expect(load().accessToken.expiresIn).toBe(3600);
		});

		it("still honours OAUTH_ACCESS_TOKEN_EXPIRES_IN as the default", () => {
			expect(lifetime({ OAUTH_ACCESS_TOKEN_EXPIRES_IN: "900" })).toEqual({
				defaultExpiresIn: 900,
				maxExpiresIn: 900,
			});
		});

		it("reads OAUTH_ACCESS_TOKEN_DEFAULT_EXPIRES_IN over the deprecated variable", () => {
			const env = {
				OAUTH_ACCESS_TOKEN_EXPIRES_IN: "900",
				OAUTH_ACCESS_TOKEN_DEFAULT_EXPIRES_IN: "600",
			};
			expect(lifetime(env)).toEqual({ defaultExpiresIn: 600, maxExpiresIn: 600 });
			expect(load(env).accessToken.expiresIn).toBe(600);
		});

		it("reads OAUTH_ACCESS_TOKEN_MAX_EXPIRES_IN", () => {
			expect(lifetime({ OAUTH_ACCESS_TOKEN_MAX_EXPIRES_IN: "7200" })).toEqual({
				defaultExpiresIn: 3600,
				maxExpiresIn: 7200,
			});
		});

		it("refuses a default variable above the max variable", () => {
			expect(() =>
				load({
					OAUTH_ACCESS_TOKEN_DEFAULT_EXPIRES_IN: "7200",
					OAUTH_ACCESS_TOKEN_MAX_EXPIRES_IN: "3600",
				}),
			).toThrow(/defaultExpiresIn.*maxExpiresIn/s);
		});

		it("refuses a max below the shipped default when the default is not lowered", () => {
			expect(() => load({ OAUTH_ACCESS_TOKEN_MAX_EXPIRES_IN: "1800" })).toThrow(/maxExpiresIn/);
		});

		it.each([
			"OAUTH_ACCESS_TOKEN_DEFAULT_EXPIRES_IN",
			"OAUTH_ACCESS_TOKEN_MAX_EXPIRES_IN",
			"OAUTH_ACCESS_TOKEN_EXPIRES_IN",
		])("refuses an exported-but-empty %s rather than reading it as zero", (name) => {
			expect(() => load({ [name]: "" })).toThrow();
		});

		it("keeps an application layer's override of the deprecated key deciding the default", () => {
			expect(lifetime({}, "oauth.accessToken.expiresIn = 900")).toEqual({
				defaultExpiresIn: 900,
				maxExpiresIn: 900,
			});
		});

		it("lets an application layer's defaultExpiresIn outrank the shipped literal on the deprecated key", () => {
			const conf = "oauth.accessToken { defaultExpiresIn = 300, maxExpiresIn = 1200 }";
			expect(lifetime({}, conf)).toEqual({ defaultExpiresIn: 300, maxExpiresIn: 1200 });
			expect(load({}, conf).accessToken.expiresIn).toBe(300);
		});
	});
});
