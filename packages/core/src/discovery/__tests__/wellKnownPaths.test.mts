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
import { discoveryPathsFor } from "#/discovery/wellKnownPaths.mjs";

/**
 * #528 — where the one metadata document is served, per issuer shape. OIDC
 * Discovery appends its suffix to the issuer; RFC 8414 inserts its well-known
 * string between host and path. Both forms are served from one home.
 */
describe("discoveryPathsFor (#528)", () => {
	it("serves the two root forms for an issuer with no path", () => {
		expect(discoveryPathsFor("https://auth.example")).toEqual({
			oidc: ["/.well-known/openid-configuration"],
			oauth: ["/.well-known/oauth-authorization-server"],
		});
		// A trailing slash is not a path.
		expect(discoveryPathsFor("https://auth.example/")).toEqual(
			discoveryPathsFor("https://auth.example"),
		);
	});

	it("appends for OIDC and inserts for RFC 8414 when the issuer has a path", () => {
		expect(discoveryPathsFor("https://auth.example/tenant-a")).toEqual({
			oidc: ["/.well-known/openid-configuration", "/tenant-a/.well-known/openid-configuration"],
			oauth: ["/.well-known/oauth-authorization-server/tenant-a"],
		});
		expect(discoveryPathsFor("https://auth.example/a/b/")).toEqual({
			oidc: ["/.well-known/openid-configuration", "/a/b/.well-known/openid-configuration"],
			oauth: ["/.well-known/oauth-authorization-server/a/b"],
		});
	});

	it("falls back to the root forms for no issuer, or one that is not a URL", () => {
		const root = {
			oidc: ["/.well-known/openid-configuration"],
			oauth: ["/.well-known/oauth-authorization-server"],
		};
		expect(discoveryPathsFor(undefined)).toEqual(root);
		expect(discoveryPathsFor("")).toEqual(root);
		expect(discoveryPathsFor("not a url")).toEqual(root);
	});
});
