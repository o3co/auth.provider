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
 * #278: the bridge used to return only `{ clientId, clientSecret, callbackURL }`,
 * dropping the four fields the redirect policy reads. Nothing failed — the
 * policy was simply constructed with an empty config, and the generated app
 * silently ran without a redirect allowlist. These tests fail if the bridge
 * stops forwarding any of them.
 */

import type { GoogleProviderConfig } from "@o3co/auth-provider-federation-google";
import { describe, expect, it } from "vitest";
import { googleFederationConfigModule } from "../modules.mjs";

type ConfigFactory = (deps: { config: unknown }) => GoogleProviderConfig;

const bridge = (
	googleFederationConfigModule as unknown as {
		provides: { googleFederationConfig: ConfigFactory };
	}
).provides.googleFederationConfig;

/** Runs the bridge over a `federations.google` section in the flat shape. */
function buildConfig(googleSection: Record<string, unknown>): GoogleProviderConfig {
	return bridge({ config: { federations: { google: { enabled: true, ...googleSection } } } });
}

const credentials = {
	clientId: "id",
	clientSecret: "secret",
	callbackURL: "https://auth.example.com/session/oauth/federation/google/callback",
};

describe("googleFederationConfigModule — redirect-policy plumbing (#278)", () => {
	it("forwards sessionDomain, authCallbackUrl, clientUrl and redirectAllowlist", () => {
		const out = buildConfig({
			...credentials,
			sessionDomain: ".example.com",
			authCallbackUrl: "https://app.example.com/auth/callback",
			clientUrl: "https://app.example.com/",
			redirectAllowlist: ["https://app.example.com/dashboard"],
		});

		expect(out).toMatchObject({
			...credentials,
			sessionDomain: ".example.com",
			authCallbackUrl: "https://app.example.com/auth/callback",
			clientUrl: "https://app.example.com/",
			redirectAllowlist: ["https://app.example.com/dashboard"],
		});
	});

	it("omits the optional fields when the operator did not configure them", () => {
		const out = buildConfig(credentials);

		expect(out).toEqual(credentials);
		expect("sessionDomain" in out).toBe(false);
		expect("authCallbackUrl" in out).toBe(false);
		expect("clientUrl" in out).toBe(false);
		expect("redirectAllowlist" in out).toBe(false);
	});

	it("rejects a redirectAllowlist that is not an array", () => {
		expect(() =>
			buildConfig({ ...credentials, redirectAllowlist: "https://app.example.com/dashboard" }),
		).toThrow(/redirectAllowlist/);
	});

	it("rejects a redirectAllowlist holding a non-string", () => {
		expect(() => buildConfig({ ...credentials, redirectAllowlist: [42] })).toThrow(
			/redirectAllowlist/,
		);
	});

	it("rejects a non-string sessionDomain rather than forwarding it", () => {
		expect(() => buildConfig({ ...credentials, sessionDomain: 42 })).toThrow(/sessionDomain/);
	});

	it("still rejects a section missing the credentials", () => {
		expect(() => buildConfig({ clientId: "id" })).toThrow(/clientId, clientSecret, callbackURL/);
	});

	it("reads through the nested federation shape as well as the flat one", () => {
		const out = bridge({
			config: {
				federations: {
					google: {
						enabled: true,
						type: "google",
						sessionDomain: ".example.com",
						redirectAllowlist: ["https://app.example.com/dashboard"],
						google: credentials,
					},
				},
			},
		});
		expect(out.sessionDomain).toBe(".example.com");
		expect(out.redirectAllowlist).toEqual(["https://app.example.com/dashboard"]);
	});
});

describe("googleFederationConfigModule — requireAuthorizationResponseIss (#597)", () => {
	it("is absent by default, so the provider's own default (required) applies", () => {
		expect("requireAuthorizationResponseIss" in buildConfig(credentials)).toBe(false);
	});

	it("forwards the operator's escape hatch", () => {
		expect(
			buildConfig({ ...credentials, requireAuthorizationResponseIss: false })
				.requireAuthorizationResponseIss,
		).toBe(false);
		expect(
			buildConfig({ ...credentials, requireAuthorizationResponseIss: true })
				.requireAuthorizationResponseIss,
		).toBe(true);
	});

	it("reads the strings an environment override produces", () => {
		expect(
			buildConfig({ ...credentials, requireAuthorizationResponseIss: "false" })
				.requireAuthorizationResponseIss,
		).toBe(false);
		expect(
			buildConfig({ ...credentials, requireAuthorizationResponseIss: "true" })
				.requireAuthorizationResponseIss,
		).toBe(true);
	});

	it("reads the spellings every other env-overridable boolean accepts", () => {
		for (const [raw, expected] of [
			["False", false],
			[" false ", false],
			["0", false],
			["TRUE", true],
			["1", true],
		] as const) {
			expect(
				buildConfig({ ...credentials, requireAuthorizationResponseIss: raw })
					.requireAuthorizationResponseIss,
			).toBe(expected);
		}
	});

	it("refuses an empty value, which elsewhere reads as false: exported-but-empty must not switch this check off", () => {
		expect(() => buildConfig({ ...credentials, requireAuthorizationResponseIss: "" })).toThrow(
			/federations\.google\.requireAuthorizationResponseIss/,
		);
	});

	it("refuses anything else: a typo must not silently switch the check off, or leave it on", () => {
		for (const bad of ["no", "off", 0, 1, []]) {
			expect(() => buildConfig({ ...credentials, requireAuthorizationResponseIss: bad })).toThrow(
				/federations\.google\.requireAuthorizationResponseIss/,
			);
		}
	});
});

describe("googleFederationConfigModule — accessType", () => {
	// federation-google asks every sign-in for consent with offline access, so
	// every session gets a refresh token; "online" is the operator's way to
	// keep Google's consent screen to the first sign-in, at the price of no
	// refresh token at all. A bridge that drops the field leaves the operator
	// without that choice.
	it("is absent by default, so the provider's own default (offline) applies", () => {
		expect("accessType" in buildConfig(credentials)).toBe(false);
	});

	it("forwards offline and online", () => {
		expect(buildConfig({ ...credentials, accessType: "online" }).accessType).toBe("online");
		expect(buildConfig({ ...credentials, accessType: "offline" }).accessType).toBe("offline");
	});

	it("refuses anything else at boot, naming the key", () => {
		for (const bad of ["", "offine", "Online", "true", false, 1]) {
			expect(() => buildConfig({ ...credentials, accessType: bad })).toThrow(
				/federations\.google\.accessType/,
			);
		}
	});
});
