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

import type { AppConfig } from "@o3co/auth-provider-core";
import { makeValidAppConfig } from "@o3co/auth-provider-core/testing";
import { describe, expect, it } from "vitest";
import { buildModules } from "../buildModules.mjs";
import { oidcFederationConfigModule } from "../modules.mjs";

/**
 * #524: the scaffold turns every enabled `federations.<name>` of type
 * `oidc` into one instance of the generic OIDC federation module, fed by a
 * single config bridge. A deployment adds an IdP with configuration only.
 */
type Factory = (deps: { config: unknown }) => Record<string, unknown>;

const bridge = (
	oidcFederationConfigModule as unknown as {
		provides: { oidcFederationConfigs: Factory };
	}
).provides.oidcFederationConfigs;

const okta = {
	issuer: "https://dev-1.okta.test",
	clientId: "okta-client",
	clientSecret: "okta-secret",
	callbackURL: "https://auth.test/session/oauth/federation/okta/callback",
};

/** Core's valid fixture, with the federations under test and every adapter on memory. */
const configWith = (federations: Record<string, unknown>): AppConfig => {
	const base = makeValidAppConfig();
	return {
		...base,
		federations,
		oauth: { ...base.oauth, code: { adapter: "memory" } },
	} as unknown as AppConfig;
};

describe("oidcFederationConfigModule (#524)", () => {
	it("has the scaffold's module name and reads config", () => {
		expect(oidcFederationConfigModule.name).toBe("standalone:oidc-federation-config");
		expect(oidcFederationConfigModule.requires).toEqual(["config"]);
	});

	it("reads every enabled oidc section into the slot, keyed by federation name", () => {
		const out = bridge({
			config: {
				federations: {
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
					google: {
						enabled: true,
						clientId: "g",
						clientSecret: "s",
						callbackURL: "https://auth.test/g",
					},
					paused: { enabled: false, type: "oidc", ...okta },
				},
			},
		});
		expect(Object.keys(out).sort()).toEqual(["keycloak", "okta"]);
		expect(out.okta).toEqual(okta);
		expect(out.keycloak).toMatchObject({
			issuer: "https://kc.test/realms/dev",
			clientUrl: "https://app.test/",
		});
	});

	it("refuses a malformed section at boot, naming the field", () => {
		const { issuer: _dropped, ...noIssuer } = okta;
		expect(() =>
			bridge({ config: { federations: { okta: { enabled: true, type: "oidc", ...noIssuer } } } }),
		).toThrow(/federations\.okta\.issuer/);
	});

	it("is an empty slot when no section is of type oidc", () => {
		expect(bridge({ config: { federations: { google: { enabled: false } } } })).toEqual({});
	});
});

describe("buildModules gating for OIDC federations (#524)", () => {
	it("lists one federation:oidc:<name> per enabled section, plus the bridge once", () => {
		const names = buildModules(
			configWith({
				okta: { enabled: true, type: "oidc", ...okta },
				keycloak: { enabled: true, type: "oidc", ...okta },
				google: { enabled: false },
			}),
		).map((m) => m.name);
		expect(names).toContain("federation:oidc:okta");
		expect(names).toContain("federation:oidc:keycloak");
		expect(names.filter((n) => n === "standalone:oidc-federation-config")).toHaveLength(1);
		expect(names).not.toContain("federation:google");
	});

	it("a google section of type oidc is the generic provider, not the built-in Google pair", () => {
		// The section's `type` names the implementation. Composing both would
		// contribute the same federation and redirect-policy keys twice.
		const names = buildModules(
			configWith({ google: { enabled: true, type: "oidc", ...okta } }),
		).map((m) => m.name);
		expect(names).toContain("federation:oidc:google");
		expect(names).not.toContain("federation:google");
		expect(names).not.toContain("standalone:google-federation-config");
	});

	it("lists nothing OIDC when no section is enabled (the shipped default)", () => {
		const names = buildModules(
			configWith({ google: { enabled: false }, oidc: { enabled: false, type: "oidc" } }),
		).map((m) => m.name);
		expect(names.some((n) => n.startsWith("federation:oidc:"))).toBe(false);
		expect(names).not.toContain("standalone:oidc-federation-config");
	});
});
