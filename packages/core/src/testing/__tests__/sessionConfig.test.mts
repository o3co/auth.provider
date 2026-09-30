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
 * The builders core's testing entry offers for the `session` and
 * `federations` sections, so a test that boots a login over plain HTTP, or
 * with a federation, writes neither section by hand.
 */

import { describe, expect, it } from "vitest";
import { AppConfigSchema } from "#/config/application.schema.mjs";
import { makeValidAppConfig, withFederation, withInsecureSessionCookie } from "#/testing/index.mjs";

describe("withInsecureSessionCookie", () => {
	it("answers a copy whose session cookie a plain-HTTP client keeps: not Secure, and so no __Host- name", () => {
		const config = makeValidAppConfig();
		const insecure = withInsecureSessionCookie(config);
		expect(insecure.session.secure).toBe(false);
		expect(insecure.session.name.startsWith("__Host-")).toBe(false);
		expect(AppConfigSchema.parse(insecure).session).toMatchObject({
			secure: false,
			name: insecure.session.name,
		});
	});

	it("keeps every other key, and leaves the configuration it was given as it was", () => {
		const config = makeValidAppConfig();
		const insecure = withInsecureSessionCookie(config);
		expect({ ...insecure, session: config.session }).toEqual(config);
		expect({ ...insecure.session, name: config.session.name, secure: true }).toEqual(
			config.session,
		);
		expect(config.session.secure).toBe(true);
	});
});

describe("withFederation", () => {
	it("answers a copy with federations.<name> an enabled entry: its callback URL and client credentials", () => {
		const config = withFederation(makeValidAppConfig(), "stub", {
			callbackURL: "https://auth.test/session/oauth/federation/stub/callback",
		});
		expect(config.federations.stub).toEqual({
			enabled: true,
			clientId: "stub-client",
			clientSecret: "stub-secret",
			callbackURL: "https://auth.test/session/oauth/federation/stub/callback",
		});
		expect(AppConfigSchema.parse(config).federations.stub).toMatchObject({ enabled: true });
	});

	it("keeps the federations already there, and leaves the configuration it was given as it was", () => {
		const base = makeValidAppConfig();
		const one = withFederation(base, "first", { callbackURL: "https://auth.test/first" });
		const two = withFederation(one, "second", {
			callbackURL: "https://auth.test/second",
			clientId: "client-2",
			clientSecret: "secret-2",
		});
		expect(Object.keys(two.federations)).toEqual(["first", "second"]);
		expect(two.federations.second).toMatchObject({
			clientId: "client-2",
			clientSecret: "secret-2",
		});
		expect(base.federations).toEqual({});
		expect(Object.keys(one.federations)).toEqual(["first"]);
	});
});
