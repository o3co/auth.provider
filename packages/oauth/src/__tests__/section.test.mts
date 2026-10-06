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
 * The oauth module's section schema, `oauth {}`: every key it declares, read
 * as the string an environment variable carries, each refused value named at
 * its path, and every object level strict — a key it does not declare is
 * refused at its path, never dropped.
 */

import {
	checkAcrValueName,
	MAX_DURATION_SECONDS,
	resolveAccessTokenLifetime,
	resolveRefreshTokenLifetime,
} from "@o3co/auth-provider-core";
import { parseString } from "@o3co/ts.hocon";
import { describe, expect, it } from "vitest";
import { oauthSectionSchema } from "#/section.mjs";

/** A section every key of which is valid: what the package's reference loads to, with an issuer. */
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
	revocation: { accessToken: "denylist" },
});

/** `valid()` with `value` at the dotted `path` (`undefined` removes the key). */
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

type Issue = { path: string; message: string; code: string };

const issuesOf = (input: unknown): Issue[] => {
	const result = oauthSectionSchema.safeParse(input);
	return result.success
		? []
		: result.error.issues.map((issue) => ({
				path: issue.path.map(String).join("."),
				message: issue.message,
				code: issue.code,
			}));
};

const messagesAt = (input: unknown, path: string): string[] =>
	issuesOf(input)
		.filter((issue) => issue.path === path)
		.map((issue) => issue.message);

describe("the section parses what the package's reference loads to", () => {
	it("accepts a section with every key valid", () => {
		expect(issuesOf(valid())).toEqual([]);
	});

	it("needs no optional level", () => {
		const required = {
			jwt: { issuer: "https://auth.test" },
			accessToken: { expiresIn: 3600 },
			refreshToken: { expiresIn: 86400 },
			oidcMode: "oidc-required",
		};
		expect(issuesOf(required)).toEqual([]);
	});

	it.each(["jwt", "accessToken", "refreshToken", "oidcMode"])("requires %s", (key) => {
		expect(issuesOf(withValue(key, undefined)).map((issue) => issue.path)).toContain(key);
	});
});

describe("every level refuses a key it does not declare, at its path", () => {
	it.each([
		["the section", ""],
		["jwt", "jwt"],
		["accessToken", "accessToken"],
		["refreshToken", "refreshToken"],
		["authorize", "authorize"],
		["nonce", "nonce"],
		["resourceIndicator", "resourceIndicator"],
		["consentPage", "consentPage"],
		["clientIdMetadataDocuments", "clientIdMetadataDocuments"],
		["revocation", "revocation"],
	])("%s", (_level, path) => {
		const input = withValue(path === "" ? "unexpected" : `${path}.unexpected`, true);
		expect(issuesOf(input)).toEqual([
			{ path, message: 'Unrecognized key: "unexpected"', code: "unrecognized_keys" },
		]);
	});

	it.each([
		"grants",
		"code",
		"deviceAuthorization",
		"tokenExchange",
		"mtls",
		"dpop",
		"tokenBinding",
		"jwt.signingKey",
	])("accepts %s, a path another section moved from, only as an empty object or null", (path) => {
		expect(issuesOf(withValue(path, {}))).toEqual([]);
		expect(issuesOf(withValue(path, null))).toEqual([]);
		expect(issuesOf(withValue(path, { enabled: true }))).toEqual([
			{ path, message: 'Unrecognized key: "enabled"', code: "unrecognized_keys" },
		]);
		expect(issuesOf(withValue(path, "on")).map((issue) => issue.path)).toEqual([path]);
	});

	it.each(["jwt.jwksPath", "jwt.jwksCacheMaxAge"])(
		"does not declare %s, a setting the JWKS section moved from",
		(path) => {
			expect(issuesOf(withValue(path, "/jwks.json"))).toEqual([
				{
					path: "jwt",
					message: `Unrecognized key: "${path.slice("jwt.".length)}"`,
					code: "unrecognized_keys",
				},
			]);
		},
	);

	it("does not declare oauth.jwt's flat key fields, which core retired and refuses naming what became of them", () => {
		expect(issuesOf(withValue("jwt", { issuer: "https://auth.test", algorithm: "HS256" }))).toEqual(
			[{ path: "jwt", message: 'Unrecognized key: "algorithm"', code: "unrecognized_keys" }],
		);
	});

	it.each([
		[
			"oauth.refreshToken.legacyTokenCompat",
			"refreshToken.legacyTokenCompat",
			false,
			"legacyTokenCompat",
		],
		[
			"oauth.refreshToken.legacyTokenCompat",
			"refreshToken.legacyTokenCompat",
			true,
			"legacyTokenCompat",
		],
		[
			"oauth.authorize.allowUnmarkedClients",
			"authorize.allowUnmarkedClients",
			false,
			"allowUnmarkedClients",
		],
		[
			"oauth.authorize.allowUnmarkedClients",
			"authorize.allowUnmarkedClients",
			true,
			"allowUnmarkedClients",
		],
	])(
		"does not declare %s, which the module's section declares removed (relocatedFrom) and boot refuses before parsing",
		(_what, path, value, key) => {
			const found = issuesOf(withValue(path, value));
			expect(found).toEqual([
				{
					path: path.slice(0, path.lastIndexOf(".")),
					message: `Unrecognized key: "${key}"`,
					code: "unrecognized_keys",
				},
			]);
		},
	);
});

describe("oauth.jwt", () => {
	describe("issuer", () => {
		it("is required", () => {
			expect(issuesOf(withValue("jwt.issuer", undefined)).map((issue) => issue.path)).toEqual([
				"jwt.issuer",
			]);
		});

		it.each([
			"https://auth.example.com",
			"https://auth.example.com/tenant-a",
			"http://localhost:3000",
			"http://127.0.0.1:3000",
			"http://[::1]:3000",
		])("accepts %s", (issuer) => {
			expect(issuesOf(withValue("jwt.issuer", issuer))).toEqual([]);
		});

		it.each([
			["a bare host, the shape a Host header would have supplied", "auth.example.com:3000"],
			["a non-loopback http URL", "http://auth.example.com"],
			["a query string", "https://auth.example.com?tenant=a"],
			["a fragment", "https://auth.example.com#a"],
			["an empty issuer", ""],
		])("refuses %s, naming the key", (_what, issuer) => {
			const messages = messagesAt(withValue("jwt.issuer", issuer), "jwt.issuer");
			expect(messages).toHaveLength(1);
			expect(messages[0]).toMatch(/^oauth\.jwt\.issuer /);
		});

		it.each(["https://auth.example.com/", "https://auth.example.com/tenant-a/"])(
			"refuses %s: a trailing slash",
			(issuer) => {
				expect(messagesAt(withValue("jwt.issuer", issuer), "jwt.issuer")).toEqual([
					"oauth.jwt.issuer must not end with a slash",
				]);
			},
		);
	});
});

describe("oauth.accessToken", () => {
	const parseAccessToken = (accessToken: unknown) =>
		(oauthSectionSchema.parse(withValue("accessToken", accessToken)) as { accessToken: unknown })
			.accessToken;

	it("keeps the deprecated alias working on its own, leaving the new keys absent", () => {
		expect(parseAccessToken({ expiresIn: 900 })).toEqual({ expiresIn: 900 });
	});

	it("mirrors defaultExpiresIn onto expiresIn", () => {
		expect(parseAccessToken({ defaultExpiresIn: 600 })).toEqual({
			defaultExpiresIn: 600,
			expiresIn: 600,
		});
	});

	it("overwrites a differing expiresIn with defaultExpiresIn", () => {
		expect(parseAccessToken({ expiresIn: 3600, defaultExpiresIn: 600 })).toEqual({
			defaultExpiresIn: 600,
			expiresIn: 600,
		});
	});

	it("keeps maxExpiresIn as given", () => {
		expect(parseAccessToken({ defaultExpiresIn: 600, maxExpiresIn: 3600 })).toEqual({
			defaultExpiresIn: 600,
			maxExpiresIn: 3600,
			expiresIn: 600,
		});
	});

	it("is idempotent, so a configuration parsed twice is unchanged", () => {
		const once = parseAccessToken({ expiresIn: 3600, defaultExpiresIn: 600, maxExpiresIn: 900 });
		expect(parseAccessToken(once)).toEqual(once);
	});

	it("refuses a default above the max at maxExpiresIn, naming both keys", () => {
		expect(
			issuesOf(withValue("accessToken", { defaultExpiresIn: 7200, maxExpiresIn: 3600 })),
		).toEqual([
			{
				path: "accessToken.maxExpiresIn",
				message:
					"oauth.accessToken.defaultExpiresIn (7200) must not exceed oauth.accessToken.maxExpiresIn (3600): lower the default or raise the max",
				code: "custom",
			},
		]);
	});

	it("refuses a default read from the deprecated alias above the max, saying where it came from", () => {
		expect(
			messagesAt(
				withValue("accessToken", { expiresIn: 3600, maxExpiresIn: 1800 }),
				"accessToken.maxExpiresIn",
			),
		).toEqual([
			"oauth.accessToken.defaultExpiresIn (3600, read from the deprecated oauth.accessToken.expiresIn) must not exceed oauth.accessToken.maxExpiresIn (1800): lower the default or raise the max",
		]);
	});

	it.each([{}, { maxExpiresIn: 600 }])(
		"refuses %j at defaultExpiresIn: neither the default nor its alias is set",
		(accessToken) => {
			expect(
				messagesAt(withValue("accessToken", accessToken), "accessToken.defaultExpiresIn"),
			).toEqual([
				"oauth.accessToken.defaultExpiresIn is required (OAUTH_ACCESS_TOKEN_DEFAULT_EXPIRES_IN); the deprecated oauth.accessToken.expiresIn is still read in its place",
			]);
		},
	);

	// The rules are core's resolver's, which every grant reads the lifetime
	// through: what one refuses the other refuses, in the same words.
	it.each([
		[{ expiresIn: 900 }],
		[{ defaultExpiresIn: 600 }],
		[{ defaultExpiresIn: 600, expiresIn: 3600 }],
		[{ defaultExpiresIn: 600, maxExpiresIn: 600 }],
		[{ defaultExpiresIn: 600, maxExpiresIn: 3600 }],
		[{ defaultExpiresIn: 7200, maxExpiresIn: 3600 }],
		[{ expiresIn: 3600, maxExpiresIn: 1800 }],
		[{ defaultExpiresIn: 600, expiresIn: 3600, maxExpiresIn: 900 }],
		[{}],
		[{ maxExpiresIn: 600 }],
	])("refuses %j exactly as resolveAccessTokenLifetime does", (accessToken) => {
		const messages = issuesOf(withValue("accessToken", accessToken)).map((issue) => issue.message);
		const resolve = () => resolveAccessTokenLifetime({ oauth: { accessToken } });
		if (messages.length === 0) {
			expect(resolve).not.toThrow();
		} else {
			expect(messages).toHaveLength(1);
			expect(resolve).toThrow(new RangeError(messages[0]));
		}
	});

	it.each([0, -1])(
		"refuses the deprecated expiresIn = %j standing alone at that key, and nothing built on it",
		(expiresIn) => {
			expect(issuesOf(withValue("accessToken", { expiresIn })).map((issue) => issue.path)).toEqual([
				"accessToken.expiresIn",
			]);
		},
	);

	for (const key of ["defaultExpiresIn", "maxExpiresIn", "expiresIn"] as const) {
		for (const bad of [0, -1, MAX_DURATION_SECONDS + 1, ""]) {
			it(`refuses ${key} = ${JSON.stringify(bad)} at that key, and nothing built on it`, () => {
				const input = withValue("accessToken", {
					defaultExpiresIn: 600,
					maxExpiresIn: 600,
					[key]: bad,
				});
				expect(issuesOf(input).map((issue) => issue.path)).toEqual([`accessToken.${key}`]);
			});
		}
	}
});

describe("oauth.refreshToken", () => {
	it("reads a refreshToken carrying its lifetime alone as given", () => {
		const parsed = oauthSectionSchema.parse(withValue("refreshToken", { expiresIn: 86400 })) as {
			refreshToken: unknown;
		};
		expect(parsed.refreshToken).toEqual({ expiresIn: 86400 });
	});

	it("requires expiresIn", () => {
		expect(issuesOf(withValue("refreshToken", {})).map((issue) => issue.path)).toEqual([
			"refreshToken.expiresIn",
		]);
	});

	it.each([1, 86_400, MAX_DURATION_SECONDS])(
		"accepts expiresIn = %j, from one second to the ceiling",
		(expiresIn) => {
			expect(issuesOf(withValue("refreshToken.expiresIn", expiresIn))).toEqual([]);
		},
	);

	// The rule is core's resolver's, which every grant that mints a refresh
	// token reads the lifetime through: a hand-built configuration meets it
	// there.
	it.each([1, 86_400, MAX_DURATION_SECONDS, 0, -1, 1.5, Number.NaN, MAX_DURATION_SECONDS + 1])(
		"judges expiresIn = %j as resolveRefreshTokenLifetime does",
		(expiresIn) => {
			const refused = issuesOf(withValue("refreshToken.expiresIn", expiresIn)).length > 0;
			const resolve = () => resolveRefreshTokenLifetime({ oauth: { refreshToken: { expiresIn } } });
			if (refused) expect(resolve).toThrow(RangeError);
			else expect(resolve()).toBe(expiresIn);
		},
	);

	it.each([
		["unknownFamilyPolicy", "reject"],
		["unknownFamilyPolicy", "accept"],
		["unknownFamilyPolicy", "warn"],
		["legacyRtPolicy", "reject"],
		["legacyRtPolicy", "accept-with-warning"],
	])("refuses %s = %j: a key the section no longer declares", (key, value) => {
		const issues = issuesOf(withValue(`refreshToken.${key}`, value));
		expect(issues.map((issue) => issue.path)).toEqual(["refreshToken"]);
		expect(issues[0]?.message).toContain(`"${key}"`);
	});

	it.each([0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, "1.5", MAX_DURATION_SECONDS + 1])(
		"refuses expiresIn = %j: not whole seconds within the ceiling",
		(expiresIn) => {
			expect(
				issuesOf(withValue("refreshToken.expiresIn", expiresIn)).map((issue) => issue.path),
			).toEqual(["refreshToken.expiresIn"]);
		},
	);
});

describe("oauth.authorize", () => {
	it.each([undefined, {}])("accepts %j", (authorize) => {
		expect(issuesOf(withValue("authorize", authorize))).toEqual([]);
	});

	it("reads an acr table, each entry a list or alternatives", () => {
		const acrValues = {
			"urn:example:pwd": ["pwd"],
			"urn:example:mfa": ["pwd", "mfa"],
			"urn:o3co:acr:phr": [["hwk"], ["swk"]],
		};
		const parsed = oauthSectionSchema.parse(withValue("authorize", { acrValues })) as {
			authorize?: { acrValues?: unknown };
		};
		expect(parsed.authorize?.acrValues).toEqual(acrValues);
	});

	it("reads the HOCON the template ships for it", () => {
		const authorize: unknown = parseString(
			'acrValues { "urn:o3co:acr:phr" = [["hwk"], ["swk"]] }',
		).toObject();
		const parsed = oauthSectionSchema.parse(withValue("authorize", authorize)) as {
			authorize?: unknown;
		};
		expect(parsed.authorize).toEqual({ acrValues: { "urn:o3co:acr:phr": [["hwk"], ["swk"]] } });
	});

	it.each([
		["an acr that requires nothing", []],
		["a value that is not a string", [1]],
		["an alternative that requires nothing", [["hwk"], []]],
		["only an alternative that requires nothing", [[]]],
		["an empty value in an alternative", [["hwk", ""]]],
		["a list mixing values and alternatives", ["pwd", ["hwk"]]],
		["lists nested deeper", [[["hwk"]]]],
	])("refuses %s", (_what, entry) => {
		expect(
			oauthSectionSchema.safeParse(withValue("authorize.acrValues", { "urn:x": entry })).success,
		).toBe(false);
	});

	it("refuses a table that is not a table", () => {
		expect(oauthSectionSchema.safeParse(withValue("authorize.acrValues", "urn:x")).success).toBe(
			false,
		);
	});

	it.each([
		["a space", "urn:x pwd"],
		["a tab", "urn:x\tpwd"],
		["a newline", "urn:x\n"],
		["a double quote", 'urn:"x"'],
		["a backslash", "urn:x\\y"],
		["a non-ASCII character", "urn:é"],
	])("refuses a key holding %s at the key, in core's words", (_what, key) => {
		expect(issuesOf(withValue("authorize.acrValues", { [key]: ["pwd"] }))).toEqual([
			{ path: `authorize.acrValues.${key}`, message: checkAcrValueName(key), code: "custom" },
		]);
	});

	it.each(["urn:x pwd", "urn:x\tpwd", 'urn:"x"', "urn:é"])(
		"names %j at its full path in the refusal",
		(key) => {
			expect(
				messagesAt(
					withValue("authorize.acrValues", { [key]: ["pwd"] }),
					`authorize.acrValues.${key}`,
				),
			).toEqual([expect.stringContaining(`oauth.authorize.acrValues key ${JSON.stringify(key)}`)]);
		},
	);

	it("refuses every unusable key, beside a usable one and an entry refused for its value", () => {
		const paths = issuesOf(
			withValue("authorize.acrValues", {
				"urn:x pwd": ["pwd"],
				"urn:y\tz": ["pwd"],
				"urn:ok": ["pwd"],
				"urn:none": [],
			}),
		).map((issue) => issue.path);
		expect(paths).toEqual(
			expect.arrayContaining([
				"authorize.acrValues.urn:x pwd",
				"authorize.acrValues.urn:y\tz",
				"authorize.acrValues.urn:none",
			]),
		);
		expect(paths.some((path) => path.includes("urn:ok"))).toBe(false);
	});

	it("accepts a key of any printable ASCII but the space, the double quote and the backslash", () => {
		const key = "urn:!#$%&'()*+,-./:;<=>?@[]^_`{|}~";
		expect(issuesOf(withValue("authorize.acrValues", { [key]: ["pwd"] }))).toEqual([]);
	});
});

describe("oauth.resourceIndicator", () => {
	it("is absent when omitted: the schema invents no default", () => {
		const parsed = oauthSectionSchema.parse(withValue("resourceIndicator", undefined)) as Record<
			string,
			unknown
		>;
		expect(parsed).not.toHaveProperty("resourceIndicator");
	});

	it("requires enabled once the level is set", () => {
		expect(issuesOf(withValue("resourceIndicator", {})).map((issue) => issue.path)).toEqual([
			"resourceIndicator.enabled",
		]);
	});
});

describe("oauth.consentPage", () => {
	it.each(["/consent", "/consent/page?tenant=acme", "https://consent.example.com/page"])(
		"accepts url = %j",
		(url) => {
			expect(issuesOf(withValue("consentPage.url", url))).toEqual([]);
		},
	);

	it.each(["", " ", "\t", "\n "])("refuses the url %j, naming the path and its variable", (url) => {
		expect(issuesOf(withValue("consentPage.url", url))).toEqual([
			{
				path: "consentPage.url",
				message:
					'oauth.consentPage.url must not be empty or blank: an exported-but-empty OAUTH_CONSENT_PAGE_URL reads as ""; unset it to keep the default, /consent, or set it to the consent page',
				code: "custom",
			},
		]);
	});
});

describe("oauth.oidcMode and oauth.revocation", () => {
	it.each(["oidc-required", "dual"])("accepts oidcMode = %s", (mode) => {
		expect(issuesOf(withValue("oidcMode", mode))).toEqual([]);
	});

	it.each([
		["oidcMode", "oauth-only"],
		["revocation.accessToken", "drop"],
		["revocation.subject", "none"],
	])("refuses %s = %j at its path", (path, value) => {
		expect(issuesOf(withValue(path, value)).map((issue) => issue.path)).toEqual([path]);
	});

	it("requires revocation.accessToken once revocation is set", () => {
		expect(
			issuesOf(withValue("revocation", { subject: "unsupported" })).map((issue) => issue.path),
		).toEqual(["revocation.accessToken"]);
	});

	it.each([
		[{ accessToken: "unsupported" }],
		[{ accessToken: "denylist", subject: "watermark" }],
		[{ accessToken: "denylist", subject: "unsupported" }],
	])("accepts revocation = %j", (revocation) => {
		expect(issuesOf(withValue("revocation", revocation))).toEqual([]);
	});
});

describe("every boolean reads the string an environment variable carries", () => {
	const BOOLEANS = [
		"jwt.legacyTypAccept",
		"requireEmailVerified",
		"requireGrantTypeAllowlist",
		"resourceIndicator.enabled",
		"clientIdMetadataDocuments.enabled",
	];
	const read = (parsed: unknown, path: string): unknown =>
		path
			.split(".")
			.reduce<unknown>(
				(level, key) => (level as Record<string, unknown> | undefined)?.[key],
				parsed,
			);

	describe.each(BOOLEANS)("%s", (path) => {
		it.each([
			["true", true],
			["TRUE", true],
			["1", true],
			[" true ", true],
			["false", false],
			["FALSE", false],
			["0", false],
			["", false],
			[true, true],
			[false, false],
		] as const)("reads %j as %j", (value, expected) => {
			expect(read(oauthSectionSchema.parse(withValue(path, value)), path)).toBe(expected);
		});

		it.each(["yes", "no", "on", "off", "ture", "2", 42, null])(
			"refuses %j rather than guessing, naming the accepted spellings",
			(value) => {
				expect(messagesAt(withValue(path, value), path)).toEqual([
					'must be one of "true", "false", "1" or "0" (an empty value reads as false)',
				]);
			},
		);
	});

	it("leaves an omitted optional boolean undefined rather than defaulting it", () => {
		const parsed = oauthSectionSchema.parse(withValue("requireEmailVerified", undefined)) as Record<
			string,
			unknown
		>;
		expect(parsed.requireEmailVerified).toBeUndefined();
	});

	it("leaves an omitted jwt.legacyTypAccept undefined rather than defaulting it", () => {
		const parsed = oauthSectionSchema.parse(withValue("jwt.legacyTypAccept", undefined)) as {
			jwt: Record<string, unknown>;
		};
		expect(parsed.jwt.legacyTypAccept).toBeUndefined();
	});
});

describe("every number reads decimal digits alone", () => {
	const KEYS: ReadonlyArray<readonly [path: string, set: (value: unknown) => unknown]> = [
		[
			"accessToken.defaultExpiresIn",
			(value) => withValue("accessToken", { defaultExpiresIn: value }),
		],
		[
			"accessToken.maxExpiresIn",
			(value) => withValue("accessToken", { expiresIn: 60, maxExpiresIn: value }),
		],
		["accessToken.expiresIn", (value) => withValue("accessToken", { expiresIn: value })],
		["refreshToken.expiresIn", (value) => withValue("refreshToken.expiresIn", value)],
		["nonce.maxLength", (value) => withValue("nonce", { maxLength: value })],
	];

	describe.each(KEYS)("%s", (path, set) => {
		it.each([
			"0x10",
			"1e3",
			"5.0",
			"+5",
			true,
			"",
			"  ",
			"Infinity",
			"NaN",
			Number.POSITIVE_INFINITY,
			Number.NaN,
		])("refuses %j, naming the key", (value) => {
			expect(messagesAt(set(value), path)).toEqual([
				expect.stringMatching(/^must be a whole number .*, in decimal digits$/),
			]);
		});

		it.each([[60], ["60"], [" 60 "]])("reads %j as 60", (value) => {
			expect(issuesOf(set(value))).toEqual([]);
		});
	});
});
