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
import {
	buildDiscoveryDocument,
	contributesProviderSurface,
	DiscoveryDocumentError,
} from "#/discovery/buildDocument.mjs";
import type { DiscoveryMetadata } from "#/discovery/types.mjs";

const OPTS = { issuer: "https://auth.example.com", signingAlgs: ["ES256"] };

/** A minimal pair of contributions that together satisfy the OIDC-required set. */
function completeItems(): DiscoveryMetadata[] {
	return [
		{
			// oauth-like
			endpoints: {
				authorization_endpoint: "/oauth/authorize",
				token_endpoint: "/oauth/token",
			},
			metadata: {
				response_types_supported: ["code"],
				subject_types_supported: ["public"],
			},
		},
		// jwks-like
		{ endpoints: { jwks_uri: "/.well-known/jwks.json" } },
	];
}

describe("buildDiscoveryDocument", () => {
	it("emits aggregator-owned issuer (normalized) and signing algs", () => {
		const doc = buildDiscoveryDocument(completeItems(), {
			issuer: "https://auth.example.com/", // trailing slash
			signingAlgs: ["ES256"],
		});
		expect(doc.issuer).toBe("https://auth.example.com");
		expect(doc.id_token_signing_alg_values_supported).toEqual(["ES256"]);
	});

	it("prefixes endpoint paths with the issuer identifier", () => {
		const doc = buildDiscoveryDocument(completeItems(), OPTS);
		expect(doc.authorization_endpoint).toBe("https://auth.example.com/oauth/authorize");
		expect(doc.token_endpoint).toBe("https://auth.example.com/oauth/token");
		expect(doc.jwks_uri).toBe("https://auth.example.com/.well-known/jwks.json");
	});

	it("inherits an issuer path prefix into endpoint URLs", () => {
		const doc = buildDiscoveryDocument(completeItems(), {
			issuer: "https://auth.example.com/auth",
			signingAlgs: ["ES256"],
		});
		expect(doc.jwks_uri).toBe("https://auth.example.com/auth/.well-known/jwks.json");
	});

	it("concatenates + de-duplicates array metadata across contributions", () => {
		const items: DiscoveryMetadata[] = [
			...completeItems(),
			{ metadata: { scopes_supported: ["openid", "profile"] } },
			{ metadata: { scopes_supported: ["profile", "email"] } },
		];
		const doc = buildDiscoveryDocument(items, OPTS);
		expect(doc.scopes_supported).toEqual(["openid", "profile", "email"]);
	});

	it("de-duplicates signing algs", () => {
		const doc = buildDiscoveryDocument(completeItems(), {
			issuer: OPTS.issuer,
			signingAlgs: ["ES256", "ES256"],
		});
		expect(doc.id_token_signing_alg_values_supported).toEqual(["ES256"]);
	});

	it("accepts a scalar field contributed twice with the same value", () => {
		const items: DiscoveryMetadata[] = [
			...completeItems(),
			{ metadata: { service_documentation: "https://docs" } },
			{ metadata: { service_documentation: "https://docs" } },
		];
		expect(() => buildDiscoveryDocument(items, OPTS)).not.toThrow();
	});

	it("throws on a conflicting scalar value", () => {
		const items: DiscoveryMetadata[] = [
			...completeItems(),
			{ metadata: { op_policy_uri: "https://a" } },
			{ metadata: { op_policy_uri: "https://b" } },
		];
		expect(() => buildDiscoveryDocument(items, OPTS)).toThrow(DiscoveryDocumentError);
	});

	it("accepts an endpoint contributed twice with the same resolved URL", () => {
		const items: DiscoveryMetadata[] = [
			...completeItems(),
			{ endpoints: { token_endpoint: "/oauth/token" } },
		];
		expect(() => buildDiscoveryDocument(items, OPTS)).not.toThrow();
	});

	it("throws on a conflicting endpoint value", () => {
		const items: DiscoveryMetadata[] = [
			...completeItems(),
			{ endpoints: { token_endpoint: "/oauth/token2" } },
		];
		expect(() => buildDiscoveryDocument(items, OPTS)).toThrow(/conflicting/);
	});

	it("throws on a non-absolute endpoint path", () => {
		const items: DiscoveryMetadata[] = [{ endpoints: { jwks_uri: "keys/jwks.json" } }];
		expect(() => buildDiscoveryDocument(items, OPTS)).toThrow(/absolute path/);
	});

	it.each([
		"/",
		"//",
		"///",
	])("throws when the issuer normalizes to empty (issuer %j)", (issuer) => {
		// An all-slashes issuer survives the assemble-app gate (`length > 0`) but
		// trailing-slash normalization reduces it to "", which would emit
		// `issuer: ""` plus origin-less endpoint URLs (`/oauth/authorize`). That
		// is a misconfiguration, so the aggregator fails the boot fast rather
		// than advertising a malformed discovery document.
		expect(() =>
			buildDiscoveryDocument(completeItems(), { issuer, signingAlgs: ["ES256"] }),
		).toThrow(DiscoveryDocumentError);
	});

	it.each([
		"issuer",
		"id_token_signing_alg_values_supported",
	])("throws when a contribution sets the reserved field %s (via metadata)", (field) => {
		const items: DiscoveryMetadata[] = [...completeItems(), { metadata: { [field]: ["x"] } }];
		expect(() => buildDiscoveryDocument(items, OPTS)).toThrow(/reserved field/);
	});

	it("throws when a contribution sets a reserved field via endpoints", () => {
		const items: DiscoveryMetadata[] = [...completeItems(), { endpoints: { issuer: "/whatever" } }];
		expect(() => buildDiscoveryDocument(items, OPTS)).toThrow(/reserved field/);
	});

	it("throws on array-vs-scalar field shape conflict", () => {
		const items: DiscoveryMetadata[] = [
			...completeItems(),
			{ metadata: { acr_values_supported: ["a"] } },
			{ metadata: { acr_values_supported: "b" } },
		];
		expect(() => buildDiscoveryDocument(items, OPTS)).toThrow(DiscoveryDocumentError);
	});

	it("throws when the assembled document is missing an OIDC-required field (presence contract)", () => {
		// jwks-only: no authorization/token endpoints, no response/subject types.
		const items: DiscoveryMetadata[] = [{ endpoints: { jwks_uri: "/.well-known/jwks.json" } }];
		expect(() => buildDiscoveryDocument(items, OPTS)).toThrow(/missing OIDC-required field/);
	});

	it("throws when jwks_uri is absent (the structural anti-dangling guarantee)", () => {
		// oauth-only: everything except jwks_uri.
		const items: DiscoveryMetadata[] = [
			{
				endpoints: { authorization_endpoint: "/oauth/authorize", token_endpoint: "/oauth/token" },
				metadata: { response_types_supported: ["code"], subject_types_supported: ["public"] },
			},
		];
		expect(() => buildDiscoveryDocument(items, OPTS)).toThrow(/jwks_uri/);
	});
});

describe("contributesProviderSurface", () => {
	it("is false for no contributions", () => {
		expect(contributesProviderSurface([])).toBe(false);
	});

	it("is false for an ancillary-only contribution (jwks_uri, no authorization_endpoint)", () => {
		const items: DiscoveryMetadata[] = [{ endpoints: { jwks_uri: "/.well-known/jwks.json" } }];
		expect(contributesProviderSurface(items)).toBe(false);
	});

	it("is true once any contribution supplies authorization_endpoint", () => {
		const items: DiscoveryMetadata[] = [
			{ endpoints: { jwks_uri: "/.well-known/jwks.json" } },
			{ endpoints: { authorization_endpoint: "/oauth/authorize" } },
		];
		expect(contributesProviderSurface(items)).toBe(true);
	});

	it("is false when contributions carry only literal metadata (no endpoints)", () => {
		const items: DiscoveryMetadata[] = [{ metadata: { scopes_supported: ["openid"] } }];
		expect(contributesProviderSurface(items)).toBe(false);
	});
});
