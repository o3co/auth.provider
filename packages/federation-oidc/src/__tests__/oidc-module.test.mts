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

import { describe, expect, it } from "vitest";
import { oidcFederationModule, oidcFederationNames, readOidcFederationConfigs } from "#/module.mjs";
import type { OidcProviderConfig } from "#/oidc.mjs";

type Factory = (deps: Record<string, unknown>) => unknown;
type Contributes = {
	federations: Record<string, Factory>;
	federationRedirectPolicies: Record<string, Factory>;
};

const okta = {
	issuer: "https://dev-1.okta.test",
	clientId: "okta-client",
	clientSecret: "okta-secret",
	callbackURL: "https://auth.test/session/oauth/federation/okta/callback",
};

describe("oidcFederationModule(name) (#524)", () => {
	it("is one module per instance, named after the federation", () => {
		const mod = oidcFederationModule("okta");
		expect(mod.name).toBe("federation:oidc:okta");
		expect(mod.requires).toEqual(["oidcFederationConfigs"]);
		const contributes = mod.contributes as unknown as Contributes;
		expect(Object.keys(contributes.federations)).toEqual(["okta"]);
		expect(Object.keys(contributes.federationRedirectPolicies)).toEqual(["okta"]);
		expect(typeof contributes.federations.okta).toBe("function");
		expect(typeof contributes.federationRedirectPolicies.okta).toBe("function");
	});

	it("refuses a name that cannot be a route segment", () => {
		for (const bad of ["", "a/b", "with space", "../x", "a?b"]) {
			expect(() => oidcFederationModule(bad), bad).toThrow(/federation name/);
		}
	});

	it("each factory reads its own entry and refuses a missing one by name", () => {
		const contributes = oidcFederationModule("okta").contributes as unknown as Contributes;
		const deps = { oidcFederationConfigs: { keycloak: okta } };
		expect(() => contributes.federations.okta?.(deps)).toThrow(
			/oidcFederationConfigs[\s\S]*"okta"/,
		);
		expect(() => contributes.federationRedirectPolicies.okta?.(deps)).toThrow(
			/oidcFederationConfigs[\s\S]*"okta"/,
		);
	});

	it("builds the redirect policy from the same entry", () => {
		const contributes = oidcFederationModule("okta").contributes as unknown as Contributes;
		const policy = contributes.federationRedirectPolicies.okta?.({
			oidcFederationConfigs: { okta: { ...okta, redirectAllowlist: ["https://app.test/welcome"] } },
		}) as { validateRedirect: unknown };
		expect(typeof policy.validateRedirect).toBe("function");
	});
});

describe("readOidcFederationConfigs (#524)", () => {
	it("reads every enabled section of type oidc, flat or nested, and ignores the rest", () => {
		const out = readOidcFederationConfigs({
			okta: { enabled: true, type: "oidc", ...okta },
			keycloak: {
				enabled: true,
				type: "oidc",
				clientUrl: "https://app.test/",
				oidc: {
					issuer: "https://kc.test/realms/dev",
					clientId: "kc-client",
					clientSecret: "kc-secret",
					callbackURL: "https://auth.test/session/oauth/federation/keycloak/callback",
				},
			},
			oidc: { enabled: true, ...okta },
			off: { enabled: false, type: "oidc", ...okta },
			google: {
				enabled: true,
				clientId: "g",
				clientSecret: "s",
				callbackURL: "https://auth.test/g",
			},
		});
		expect(Object.keys(out).sort()).toEqual(["keycloak", "oidc", "okta"]);
		expect(out.okta).toEqual(okta);
		expect(out.keycloak).toMatchObject({
			issuer: "https://kc.test/realms/dev",
			clientId: "kc-client",
			clientUrl: "https://app.test/",
		});
		expect(
			oidcFederationNames({
				b: { enabled: true, type: "oidc" },
				a: { enabled: true, type: "oidc" },
			}),
		).toEqual(["a", "b"]);
	});

	it("forwards every optional field in its declared shape", () => {
		const out = readOidcFederationConfigs({
			okta: {
				enabled: true,
				type: "oidc",
				...okta,
				scopes: ["openid", "groups"],
				discovery: "false",
				endpoints: {
					authorizationEndpoint: "https://dev-1.okta.test/oauth2/v1/authorize",
					tokenEndpoint: "https://dev-1.okta.test/oauth2/v1/token",
					jwksUri: "https://dev-1.okta.test/oauth2/v1/keys",
				},
				idTokenSignedResponseAlg: "RS256",
				userInfo: true,
				clockToleranceSeconds: 10,
				redirectAllowlist: ["https://app.test/welcome"],
				sessionDomain: ".test",
				authCallbackUrl: "https://app.test/auth/callback",
				clientUrl: "https://app.test/",
			},
		});
		const config = out.okta as OidcProviderConfig;
		expect(config).toEqual({
			...okta,
			scopes: ["openid", "groups"],
			discovery: false,
			endpoints: {
				authorizationEndpoint: "https://dev-1.okta.test/oauth2/v1/authorize",
				tokenEndpoint: "https://dev-1.okta.test/oauth2/v1/token",
				jwksUri: "https://dev-1.okta.test/oauth2/v1/keys",
			},
			idTokenSignedResponseAlg: "RS256",
			userInfo: true,
			clockToleranceSeconds: 10,
			redirectAllowlist: ["https://app.test/welcome"],
			sessionDomain: ".test",
			authCallbackUrl: "https://app.test/auth/callback",
			clientUrl: "https://app.test/",
		});
		expect("privateKey" in config).toBe(false);
	});

	it("reads a private key as a PEM string or as { pem, kid, alg }", () => {
		const { clientSecret: _drop, ...noSecret } = okta;
		const pem = "-----BEGIN PRIVATE KEY-----\nMIIB...\n-----END PRIVATE KEY-----\n";
		expect(
			readOidcFederationConfigs({
				a: { enabled: true, type: "oidc", ...noSecret, privateKey: pem },
			}).a,
		).toEqual({
			...noSecret,
			privateKey: pem,
		});
		expect(
			readOidcFederationConfigs({
				a: {
					enabled: true,
					type: "oidc",
					...noSecret,
					privateKey: { pem, kid: "k1", alg: "PS256" },
				},
			}).a,
		).toEqual({ ...noSecret, privateKey: { pem, kid: "k1", alg: "PS256" } });
	});

	it("refuses a section missing what the provider cannot run without", () => {
		const { issuer: _i, ...noIssuer } = okta;
		expect(() =>
			readOidcFederationConfigs({ okta: { enabled: true, type: "oidc", ...noIssuer } }),
		).toThrow(/federations\.okta\.issuer/);
		const { callbackURL: _c, ...noCallback } = okta;
		expect(() =>
			readOidcFederationConfigs({ okta: { enabled: true, type: "oidc", ...noCallback } }),
		).toThrow(/federations\.okta\.callbackURL/);
		const { clientSecret: _s, ...noSecret } = okta;
		expect(() =>
			readOidcFederationConfigs({ okta: { enabled: true, type: "oidc", ...noSecret } }),
		).toThrow(/federations\.okta[\s\S]*clientSecret[\s\S]*privateKey/);
		expect(() =>
			readOidcFederationConfigs({
				okta: { enabled: true, type: "oidc", ...okta, privateKey: "-----BEGIN PRIVATE KEY-----" },
			}),
		).toThrow(/federations\.okta[\s\S]*clientSecret[\s\S]*privateKey/);
	});

	it("refuses fields of the wrong shape rather than dropping them", () => {
		const section = (extra: Record<string, unknown>) => ({
			okta: { enabled: true, type: "oidc", ...okta, ...extra },
		});
		expect(() => readOidcFederationConfigs(section({ scopes: "openid profile" }))).toThrow(
			/federations\.okta\.scopes/,
		);
		expect(() => readOidcFederationConfigs(section({ scopes: ["openid", 3] }))).toThrow(
			/federations\.okta\.scopes/,
		);
		expect(() => readOidcFederationConfigs(section({ endpoints: "https://x" }))).toThrow(
			/federations\.okta\.endpoints/,
		);
		expect(() => readOidcFederationConfigs(section({ endpoints: { tokenEndpoint: 1 } }))).toThrow(
			/federations\.okta\.endpoints\.tokenEndpoint/,
		);
		expect(() => readOidcFederationConfigs(section({ discovery: "yes" }))).toThrow(
			/federations\.okta\.discovery/,
		);
		expect(() => readOidcFederationConfigs(section({ userInfo: 1 }))).toThrow(
			/federations\.okta\.userInfo/,
		);
		expect(() => readOidcFederationConfigs(section({ clockToleranceSeconds: "10" }))).toThrow(
			/federations\.okta\.clockToleranceSeconds/,
		);
		expect(() => readOidcFederationConfigs(section({ redirectAllowlist: "https://x" }))).toThrow(
			/federations\.okta\.redirectAllowlist/,
		);
		expect(() => readOidcFederationConfigs(section({ sessionDomain: 42 }))).toThrow(
			/federations\.okta\.sessionDomain/,
		);
		expect(() =>
			readOidcFederationConfigs(section({ privateKey: { kid: "k" }, clientSecret: undefined })),
		).toThrow(/federations\.okta\.privateKey/);
	});
});

describe("readOidcFederationConfigs — the accumulator (#524 review)", () => {
	it("refuses a section named __proto__ by name, rather than assigning through the prototype setter", () => {
		// JSON.parse (like a config parser) creates an own "__proto__" key; an
		// object literal here would set the prototype instead.
		const federations = JSON.parse(
			'{"__proto__": {"enabled": true, "type": "oidc", "issuer": "https://idp.example.com", "clientId": "c", "clientSecret": "s", "callbackURL": "https://rp.example.com/cb"}}',
		) as Record<string, unknown>;
		expect(() => readOidcFederationConfigs(federations)).toThrow(/OIDC federation name/);
	});

	it("returns a map with no inherited members, so a name is looked up as an own entry only", () => {
		const out = readOidcFederationConfigs({});
		expect("constructor" in out).toBe(false);
		expect(Object.getPrototypeOf(out)).toBeNull();
	});
});
