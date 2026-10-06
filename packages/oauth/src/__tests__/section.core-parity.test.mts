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
 * While core's schema still declares `oauth {}`, boot parses the section with
 * it before this module's schema, so an operator meets core's refusal first.
 * The two must agree on every key both declare: what each accepts, what it
 * makes of it, and each refusal's path and message, so nothing changes for an
 * operator when core stops declaring the section. Of what core retired from
 * the section, `oauth.jwt`'s flat key fields stay core's: core refuses them
 * naming what became of them, the module as keys it does not declare. The keys
 * the module removed (`oauth.refreshToken.legacyTokenCompat`,
 * `oauth.authorize.allowUnmarkedClients`) its manifest declares removed, and
 * boot refuses them before either schema runs; a path another section moved from
 * core carries unread, the module only as an empty object or null. Boot refuses a key
 * set under a moved path naming its new one before either schema runs, while
 * the module it moved to is loaded; the refresh-token family policy keys core
 * still declares optional are such paths, and the module declares neither.
 *
 * This file goes when core's schema stops declaring `oauth {}`.
 */

import { CoreConfigSchema, checkAcrValueName } from "@o3co/auth-provider-core";
import { describe, expect, it } from "vitest";
import { oauthEndpointsModule } from "#/module.mjs";
import { oauthAuthorizationGrantsModule } from "#/oauthAuthorization.mjs";
import { oauthSectionSchema } from "#/section.mjs";

const valid = (): Record<string, unknown> => ({
	jwt: { issuer: "https://auth.test", legacyTypAccept: false },
	accessToken: { expiresIn: 3600 },
	refreshToken: { expiresIn: 86400 },
	oidcMode: "oidc-required",
	requireEmailVerified: false,
	requireGrantTypeAllowlist: false,
	authorize: { acrValues: {} },
	nonce: { maxLength: 256 },
	resourceIndicator: { enabled: false },
	consentPage: { url: "/consent" },
	clientIdMetadataDocuments: { enabled: false },
	revocation: { accessToken: "denylist", subject: "unsupported" },
});

function withValue(path: string, value: unknown): Record<string, unknown> {
	const section = valid();
	const keys = path.split(".");
	let level = section;
	for (const key of keys.slice(0, -1)) {
		const next = level[key];
		level[key] = typeof next === "object" && next !== null ? { ...next } : {};
		level = level[key] as Record<string, unknown>;
	}
	const last = keys[keys.length - 1] as string;
	if (value === undefined) delete level[last];
	else level[last] = value;
	return section;
}

/** Each parse's outcome: the output, or each issue as `path: message`, sorted. */
function outcome(schema: { safeParse: (input: unknown) => unknown }, input: unknown) {
	const result = schema.safeParse(input) as
		| { success: true; data: unknown }
		| {
				success: false;
				error: { issues: readonly { path: readonly PropertyKey[]; message: string }[] };
		  };
	return result.success
		? { data: result.data }
		: {
				issues: result.error.issues
					.map((issue) => `${issue.path.map(String).join(".")}: ${issue.message}`)
					.sort(),
			};
}

const coreOauth = CoreConfigSchema.shape.oauth;

const CASES: ReadonlyArray<readonly [path: string, value: unknown]> = [
	["jwt.issuer", undefined],
	["jwt.issuer", "auth.example.com:3000"],
	["jwt.issuer", "http://auth.example.com"],
	["jwt.issuer", "https://auth.example.com/"],
	["jwt.issuer", "https://auth.example.com?tenant=a"],
	["jwt.issuer", ""],
	["jwt.issuer", 42],
	["jwt.legacyTypAccept", "true"],
	["jwt.legacyTypAccept", ""],
	["jwt.legacyTypAccept", "on"],
	["accessToken", { expiresIn: 900 }],
	["accessToken", { defaultExpiresIn: "600" }],
	["accessToken", { expiresIn: 3600, defaultExpiresIn: 600, maxExpiresIn: " 900 " }],
	["accessToken", { defaultExpiresIn: 7200, maxExpiresIn: 3600 }],
	["accessToken", { expiresIn: 3600, maxExpiresIn: 1800 }],
	["accessToken", {}],
	["accessToken", { maxExpiresIn: 600 }],
	["accessToken", { defaultExpiresIn: 0, maxExpiresIn: 600 }],
	["accessToken", { defaultExpiresIn: "1e3" }],
	["accessToken", { expiresIn: "" }],
	["accessToken", undefined],
	["refreshToken.expiresIn", "0x10"],
	["refreshToken.expiresIn", 1.5],
	["refreshToken.expiresIn", 31_536_001],
	["oidcMode", "dual"],
	["oidcMode", "oauth-only"],
	["requireEmailVerified", "1"],
	["requireEmailVerified", "yes"],
	["requireGrantTypeAllowlist", " TRUE "],
	["requireGrantTypeAllowlist", 2],
	["authorize", undefined],
	["authorize", {}],
	["authorize.acrValues", { "urn:x": [["hwk"], ["swk"]], "urn:y": ["pwd"] }],
	["authorize.acrValues", { "urn:x": [] }],
	["authorize.acrValues", { "urn:x": ["pwd", ["hwk"]] }],
	["authorize.acrValues", "urn:x"],
	["authorize.acrValues", { "urn:x pwd": ["pwd"] }],
	["authorize.acrValues", { 'urn:"x"': ["pwd"], "urn:x\\y": ["pwd"], "urn:é": ["pwd"] }],
	["authorize.acrValues", { "urn:x\tpwd": ["pwd"], "urn:ok": ["pwd"], "urn:none": [] }],
	["authorize.acrValues", { "": ["pwd"] }],
	["nonce.maxLength", "512"],
	["nonce.maxLength", 0],
	["nonce.maxLength", "+5"],
	["resourceIndicator.enabled", "false"],
	["resourceIndicator.enabled", "off"],
	["resourceIndicator", {}],
	["revocation", { accessToken: "unsupported" }],
	["revocation", { subject: "watermark" }],
	["revocation.accessToken", "drop"],
	["revocation.subject", "none"],
	["grants", {}],
	["tokenBinding", {}],
	["jwt.signingKey", {}],
];

describe("the module's schema and core's agree on every key both declare", () => {
	it("on a valid section", () => {
		expect(outcome(oauthSectionSchema, valid())).toEqual(outcome(coreOauth, valid()));
	});

	it.each(CASES)("%s = %j", (path, value) => {
		const input = withValue(path, value);
		expect(outcome(oauthSectionSchema, input)).toEqual(outcome(coreOauth, input));
	});
});

describe("both refuse an acr value name /authorize can never be asked for, in one wording", () => {
	it.each(["urn:x pwd", "urn:x\tpwd", "urn:x\n", 'urn:"x"', "urn:x\\y", "urn:é"])(
		"%j: one issue at the key, checkAcrValueName's message, from each schema",
		(key) => {
			const input = withValue("authorize.acrValues", { [key]: ["pwd"] });
			const expected = { issues: [`authorize.acrValues.${key}: ${checkAcrValueName(key)}`] };
			expect(outcome(oauthSectionSchema, input)).toEqual(expected);
			expect(outcome(coreOauth, input)).toEqual(expected);
		},
	);
});

describe("what core retired from the section", () => {
	it("refreshToken.legacyTokenCompat and authorize.allowUnmarkedClients: the module's manifest declares them removed, so boot refuses them before either schema runs", () => {
		expect(oauthEndpointsModule.section?.relocatedFrom).toMatchObject({
			"oauth.refreshToken.legacyTokenCompat": null,
			"oauth.authorize.allowUnmarkedClients": null,
		});
	});

	it.each([
		["jwt", { issuer: "https://auth.test", algorithm: "HS256" }, "jwt", "algorithm"],
		["refreshToken.legacyTokenCompat", false, "refreshToken", "legacyTokenCompat"],
		["authorize.allowUnmarkedClients", false, "authorize", "allowUnmarkedClients"],
	])(
		"%s = %j: core's schema names what became of it, the module's refuses a key it does not declare",
		(path, value, level, key) => {
			const input = withValue(path, value);
			const core = outcome(coreOauth, input) as { issues?: string[] };
			expect(core.issues).toHaveLength(1);
			expect(core.issues?.[0]).toMatch(new RegExp(`^${level}\\.${key}: oauth\\.${level}`));
			expect(outcome(oauthSectionSchema, input)).toEqual({
				issues: [`${level}: Unrecognized key: "${key}"`],
			});
		},
	);

	it.each(["grants", "deviceAuthorization", "tokenExchange", "mtls", "dpop", "code"])(
		"%s with a key set: core carries it unread, the module refuses it",
		(path) => {
			const input = withValue(path, { enabled: true });
			expect(outcome(coreOauth, input)).toHaveProperty("data");
			expect(outcome(oauthSectionSchema, input)).toEqual({
				issues: [`${path}: Unrecognized key: "enabled"`],
			});
		},
	);
});

describe("the refresh-token family policy keys: core accepts them absent, the module declares neither", () => {
	it("a section without them parses alike in both", () => {
		expect(outcome(coreOauth, valid())).toHaveProperty("data");
		expect(outcome(oauthSectionSchema, valid())).toEqual(outcome(coreOauth, valid()));
	});

	it.each([
		["unknownFamilyPolicy", "accept"],
		["legacyRtPolicy", "reject"],
	])(
		"refreshToken.%s = %j: core carries it, the module refuses a key it does not declare",
		(key, value) => {
			const input = withValue(`refreshToken.${key}`, value);
			expect(outcome(coreOauth, input)).toHaveProperty("data");
			expect(outcome(oauthSectionSchema, input)).toEqual({
				issues: [`refreshToken: Unrecognized key: "${key}"`],
			});
		},
	);

	it("boot refuses either before a schema runs: one as moved into oauth-authorization, the other as removed", () => {
		expect(oauthAuthorizationGrantsModule.section?.relocatedFrom).toMatchObject({
			"oauth.refreshToken.unknownFamilyPolicy": "grants.refreshToken.unknownFamilyPolicy",
		});
		expect(oauthEndpointsModule.section?.relocatedFrom).toMatchObject({
			"oauth.refreshToken.legacyRtPolicy": null,
		});
	});
});
