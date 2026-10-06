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
 * What the session module's federation routes read, built from a deps
 * object with no `config`: the federations from core's `federationSettings`
 * slot, and where an account-link start may be navigated from from the
 * module's own section (`session.csrf.trustedOrigins`).
 */

import type { FederationProvider } from "@o3co/auth-provider-core";
import {
	createTestFederationSettings,
	createTestSessionCookiePolicy,
	resolverForTests,
} from "@o3co/auth-provider-core/testing";
import type { Router } from "express";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { SESSION_ADMISSION_ACTIONS } from "#/admissionActions.mjs";
import { sessionModule } from "#/module.mjs";
import {
	makeFederationTokenStore,
	makePermissivePolicy,
	makeSessionApp,
	makeUserRepository,
	makeUserSessionStore,
} from "../routes/__tests__/federation-harness.mjs";
import { fakeSessionLifecycle } from "./_helpers/sessionLifecycle.mjs";

/** A provider named `name` whose authorization URL carries the `redirectUri` the start handed it. */
const echoingProvider = (name: string): FederationProvider => ({
	name,
	scope: ["openid"],
	buildAuthorizationUrl: ({ redirectUri, state }) => {
		const url = new URL(`https://${name}.idp.test/authorize`);
		url.searchParams.set("redirect_uri", redirectUri);
		url.searchParams.set("state", state);
		return url;
	},
	exchangeCode: async () => ({ issuer: `https://${name}.idp.test`, sub: "u", expiresAt: null }),
});

/** A `form_post` provider named `apple`, whose start keeps a transaction under a cookie of its own. */
const formPostProvider: FederationProvider = {
	name: "apple",
	scope: ["email"],
	responseMode: "form_post",
	buildAuthorizationUrl: () => new URL("https://appleid.apple.test/auth/authorize"),
	exchangeCode: async () => ({ issuer: "https://appleid.apple.test", sub: "u", expiresAt: null }),
};

/** The module's section as its reference ships it, with `trustedOrigins` as given. */
const sectionWith = (trustedOrigins: readonly string[]) => ({
	redirectAllowlist: [],
	csrf: { trustedOrigins: [...trustedOrigins], ttlSeconds: 7200 },
	loginPage: { url: "/login" },
	rateLimit: { login: { windowMs: 900_000, limit: 20 } },
});

/**
 * The module's federation routes, built from deps that carry the slots and
 * the section the manifest declares and no `config`, mounted under
 * `/session` over the harness's session shim.
 */
function federationRoutes(deps: {
	federationSettings: ReturnType<typeof createTestFederationSettings>;
	trustedOrigins?: readonly string[];
	sessionCookieName?: string;
}) {
	const factory = sessionModule.contributes?.routes?.[1];
	if (factory === undefined) throw new Error("the session module contributes no federation routes");
	const contribution = (factory as (deps: unknown) => { mountPath: string; handler: Router })({
		section: sectionWith(deps.trustedOrigins ?? []),
		federationSettings: deps.federationSettings,
		federationProviders: new Map([
			["test", echoingProvider("test")],
			["apple", formPostProvider],
		]),
		federationRedirectPolicyResolver: new Map([
			["test", makePermissivePolicy()],
			["apple", makePermissivePolicy()],
		]),
		userRepository: makeUserRepository(),
		userSessionStore: makeUserSessionStore(),
		sessionLifecycle: fakeSessionLifecycle(),
		federationTokenStore: makeFederationTokenStore(),
		sessionCookiePolicy: createTestSessionCookiePolicy(
			deps.sessionCookieName === undefined ? {} : { name: deps.sessionCookieName },
		),
		sessionRequirementResolver: resolverForTests([], { actions: SESSION_ADMISSION_ACTIONS }),
	});
	const app = makeSessionApp(new Map());
	app.use(contribution.mountPath, contribution.handler);
	return app;
}

describe("the session module's federation routes read their slots and section, not config", () => {
	it("hands the start the callback URL of the enabled entry federationSettings holds", async () => {
		const app = federationRoutes({
			federationSettings: createTestFederationSettings({
				test: { type: "loose", callbackURL: "https://auth.test/cb/test" },
			}),
		});
		const res = await request(app).get("/session/oauth/federation/test");
		expect(res.status).toBe(302);
		expect(new URL(res.headers.location as string).searchParams.get("redirect_uri")).toBe(
			"https://auth.test/cb/test",
		);
	});

	it("takes no callback URL from an entry federationSettings holds disabled", async () => {
		const app = federationRoutes({
			federationSettings: createTestFederationSettings({
				test: { type: "loose", enabled: false, callbackURL: "https://auth.test/cb/test" },
			}),
		});
		const res = await request(app).get("/session/oauth/federation/test");
		expect(res.status).toBe(500);
		expect(res.body.error).toBe("misconfiguration");
	});

	it("names the transaction cookie after the session cookie sessionCookiePolicy carries", async () => {
		const app = federationRoutes({
			federationSettings: createTestFederationSettings({ apple: { type: "loose" } }),
			sessionCookieName: "__Host-acme.sid",
		});
		const res = await request(app).get("/session/oauth/federation/apple");
		expect(res.status).toBe(302);
		const header = ((res.headers["set-cookie"] as unknown as string[]) ?? []).find((c) =>
			c.includes(".federation="),
		);
		expect(header?.split("=")[0]).toBe("__Secure-acme.sid.federation");
	});

	it("lets a link start navigated from an origin on session.csrf.trustedOrigins through the origin check", async () => {
		const start = (trustedOrigins: readonly string[]) =>
			request(
				federationRoutes({
					federationSettings: createTestFederationSettings({ test: { type: "loose" } }),
					trustedOrigins,
				}),
			)
				.get("/session/oauth/federation/test?link=1")
				.set("Host", "auth.example.com")
				.set("Sec-Fetch-Site", "same-site")
				.set("Referer", "https://app.example.com/account");
		const trusted = await start(["https://app.example.com"]);
		// Past the origin check, the harness's repository cannot link.
		expect(trusted.status).toBe(400);
		expect(trusted.body.error).toBe("link_unsupported");
		const untrusted = await start([]);
		expect(untrusted.status).toBe(403);
		expect(untrusted.body.error).toBe("link_requires_trusted_origin");
	});
});
