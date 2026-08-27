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
import { resolveOAuthOptions } from "#/resolveOAuthOptions.mjs";
import { createMockLogger } from "./_helpers/mockLogger.mjs";

describe("resolveOAuthOptions", () => {
	it("carries every knob through from a schema-validated config", () => {
		const options = resolveOAuthOptions({
			oauth: {
				jwt: { issuer: "https://issuer.example", legacyTypAccept: true },
				oidcMode: "dual",
				requireEmailVerified: true,
				grants: {
					authorization_code: {
						pkce: { required: true, defaultMethod: "S256", supportedMethods: ["S256"] },
					},
				},
				nonce: { maxLength: 64 },
				resourceIndicator: { enabled: true },
			},
		});

		expect(options.issuer).toBe("https://issuer.example");
		expect(options.legacyTypAccept).toBe(true);
		expect(options.oidcMode).toBe("dual");
		expect(options.requireEmailVerified).toBe(true);
		expect(options.pkce).toEqual({
			required: true,
			defaultMethod: "S256",
			supportedMethods: ["S256"],
		});
		expect(options.nonceMaxLength).toBe(64);
		expect(options.resourceIndicatorEnabled).toBe(true);
	});

	it("tolerates a hand-built partial config (issuer only) and applies the defaults", () => {
		// The shape router tests hand-build: no oauth.grants, no oidcMode —
		// everything the zod schema would have required.
		const options = resolveOAuthOptions({
			oauth: { jwt: { issuer: "https://issuer.example" } },
		});

		expect(options.issuer).toBe("https://issuer.example");
		expect(options.legacyTypAccept).toBeUndefined();
		expect(options.oidcMode).toBe("oidc-required");
		expect(options.requireEmailVerified).toBe(false);
		expect(options.pkce).toEqual({
			required: false,
			defaultMethod: "plain",
			supportedMethods: ["S256", "plain"],
		});
		expect(options.nonceMaxLength).toBe(256);
		expect(options.resourceIndicatorEnabled).toBe(false);
	});

	it("resolves a config with no oauth block at all to pure defaults", () => {
		const options = resolveOAuthOptions({});

		expect(options.issuer).toBeUndefined();
		expect(options.legacyTypAccept).toBeUndefined();
		expect(options.oidcMode).toBe("oidc-required");
		expect(options.requireEmailVerified).toBe(false);
		expect(options.pkce).toEqual({
			required: false,
			defaultMethod: "plain",
			supportedMethods: ["S256", "plain"],
		});
		expect(options.nonceMaxLength).toBe(256);
		expect(options.resourceIndicatorEnabled).toBe(false);
	});

	it("treats the boolean opt-ins strictly — only literal `true` enables", () => {
		// A hand-built config can carry an uncoerced env-var string. The strict
		// `=== true` reads (matching the pre-#328 inline casts) must not widen.
		const options = resolveOAuthOptions({
			oauth: {
				requireEmailVerified: "true",
				resourceIndicator: { enabled: "true" },
				grants: { authorization_code: { pkce: { required: "true" } } },
			},
		});

		expect(options.requireEmailVerified).toBe(false);
		expect(options.resourceIndicatorEnabled).toBe(false);
		expect(options.pkce.required).toBe(false);
	});

	it("does not resolve the removed oauth.authorize.allowUnmarkedClients (#330)", () => {
		// A hand-built config bypasses the schema tombstone, so the resolver
		// must not carry the stale key onto the options object — the /authorize
		// handler has nothing to read even if an embedder still sets it.
		const options = resolveOAuthOptions({
			oauth: { authorize: { allowUnmarkedClients: true } },
		});

		expect("allowUnmarkedClients" in options).toBe(false);
	});

	it("keeps issuer raw so checkCanonicalIssuer stays the single validator", () => {
		// Non-string issuers must survive resolution untouched — the router's
		// checkCanonicalIssuer call is what rejects them, with its own message.
		expect(resolveOAuthOptions({ oauth: { jwt: { issuer: 123 } } }).issuer).toBe(123);
		expect(resolveOAuthOptions({ oauth: { jwt: { issuer: "" } } }).issuer).toBe("");
	});

	it("filters non-string pkce supportedMethods and warns through the given logger", () => {
		const logger = createMockLogger();
		const options = resolveOAuthOptions(
			{
				oauth: {
					grants: {
						authorization_code: { pkce: { supportedMethods: ["S256", 123, "plain"] } },
					},
				},
			},
			logger,
		);

		expect(options.pkce.supportedMethods).toEqual(["S256", "plain"]);
		expect(logger.warn).toHaveBeenCalledWith(
			expect.objectContaining({ removed: 1 }),
			"pkce_supportedMethods_non_string_filtered",
		);
	});
});
