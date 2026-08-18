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
import { buildDiscoveryDocument, DiscoveryDocumentError } from "#/discovery/buildDocument.mjs";
import type { OidcDiscoveryContribution } from "#/discovery/types.mjs";

const OPTS = { issuer: "https://auth.example.com", signingAlgs: ["ES256"] };

/** A minimal pair of contributions that together satisfy the OIDC-required set. */
function completeItems(): OidcDiscoveryContribution[] {
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
		const items: OidcDiscoveryContribution[] = [
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
		const items: OidcDiscoveryContribution[] = [
			...completeItems(),
			{ metadata: { service_documentation: "https://docs" } },
			{ metadata: { service_documentation: "https://docs" } },
		];
		expect(() => buildDiscoveryDocument(items, OPTS)).not.toThrow();
	});

	it("throws on a conflicting scalar value", () => {
		const items: OidcDiscoveryContribution[] = [
			...completeItems(),
			{ metadata: { op_policy_uri: "https://a" } },
			{ metadata: { op_policy_uri: "https://b" } },
		];
		expect(() => buildDiscoveryDocument(items, OPTS)).toThrow(DiscoveryDocumentError);
	});

	it("accepts an endpoint contributed twice with the same resolved URL", () => {
		const items: OidcDiscoveryContribution[] = [
			...completeItems(),
			{ endpoints: { token_endpoint: "/oauth/token" } },
		];
		expect(() => buildDiscoveryDocument(items, OPTS)).not.toThrow();
	});

	it("throws on a conflicting endpoint value", () => {
		const items: OidcDiscoveryContribution[] = [
			...completeItems(),
			{ endpoints: { token_endpoint: "/oauth/token2" } },
		];
		expect(() => buildDiscoveryDocument(items, OPTS)).toThrow(/conflicting/);
	});

	it("throws on a non-absolute endpoint path", () => {
		const items: OidcDiscoveryContribution[] = [{ endpoints: { jwks_uri: "keys/jwks.json" } }];
		expect(() => buildDiscoveryDocument(items, OPTS)).toThrow(/absolute path/);
	});

	it.each(["/", "//", "///"])(
		"throws when the issuer normalizes to empty (issuer %j)",
		(issuer) => {
			// An all-slashes issuer survives the assemble-app gate (`length > 0`) but
			// trailing-slash normalization reduces it to "", which would emit
			// `issuer: ""` plus origin-less endpoint URLs (`/oauth/authorize`). That
			// is a misconfiguration, so the aggregator fails the boot fast rather
			// than advertising a malformed discovery document.
			expect(() =>
				buildDiscoveryDocument(completeItems(), { issuer, signingAlgs: ["ES256"] }),
			).toThrow(DiscoveryDocumentError);
		},
	);

	it.each(["issuer", "id_token_signing_alg_values_supported"])(
		"throws when a contribution sets the reserved field %s (via metadata)",
		(field) => {
			const items: OidcDiscoveryContribution[] = [
				...completeItems(),
				{ metadata: { [field]: ["x"] } },
			];
			expect(() => buildDiscoveryDocument(items, OPTS)).toThrow(/reserved field/);
		},
	);

	it("throws when a contribution sets a reserved field via endpoints", () => {
		const items: OidcDiscoveryContribution[] = [
			...completeItems(),
			{ endpoints: { issuer: "/whatever" } },
		];
		expect(() => buildDiscoveryDocument(items, OPTS)).toThrow(/reserved field/);
	});

	it("throws on array-vs-scalar field shape conflict", () => {
		const items: OidcDiscoveryContribution[] = [
			...completeItems(),
			{ metadata: { acr_values_supported: ["a"] } },
			{ metadata: { acr_values_supported: "b" } },
		];
		expect(() => buildDiscoveryDocument(items, OPTS)).toThrow(DiscoveryDocumentError);
	});

	it("throws when the assembled document is missing an OIDC-required field (presence contract)", () => {
		// jwks-only: no authorization/token endpoints, no response/subject types.
		const items: OidcDiscoveryContribution[] = [
			{ endpoints: { jwks_uri: "/.well-known/jwks.json" } },
		];
		expect(() => buildDiscoveryDocument(items, OPTS)).toThrow(/missing OIDC-required field/);
	});

	it("throws when jwks_uri is absent (the structural anti-dangling guarantee)", () => {
		// oauth-only: everything except jwks_uri.
		const items: OidcDiscoveryContribution[] = [
			{
				endpoints: { authorization_endpoint: "/oauth/authorize", token_endpoint: "/oauth/token" },
				metadata: { response_types_supported: ["code"], subject_types_supported: ["public"] },
			},
		];
		expect(() => buildDiscoveryDocument(items, OPTS)).toThrow(/jwks_uri/);
	});

	it("throws when no signing algorithms are provided (empty id_token_signing_alg_values_supported is OIDC-invalid)", () => {
		// An empty `signingAlgs` would otherwise pass the REQUIRED_FIELDS check
		// (the array is present, just empty) yet advertise a document no RP can
		// use to verify id_tokens — a silent non-compliance. Fail the boot fast.
		expect(() =>
			buildDiscoveryDocument(completeItems(), { issuer: OPTS.issuer, signingAlgs: [] }),
		).toThrow(/signing alg/i);
	});

	it("rejects an endpoint field (`*_endpoint`) contributed via `metadata` instead of `endpoints`", () => {
		// `metadata` fields are emitted literally (no absolute-path validation, no
		// issuer prefixing). An endpoint contributed there would advertise a
		// relative/origin-less URL. Endpoint fields MUST go through `endpoints`.
		const items: OidcDiscoveryContribution[] = [
			...completeItems(),
			{ metadata: { revocation_endpoint: "/oauth/revoke" } },
		];
		expect(() => buildDiscoveryDocument(items, OPTS)).toThrow(/endpoints/);
	});

	it("rejects `jwks_uri` contributed via `metadata` instead of `endpoints`", () => {
		const items: OidcDiscoveryContribution[] = [
			{
				endpoints: { authorization_endpoint: "/oauth/authorize", token_endpoint: "/oauth/token" },
				metadata: {
					response_types_supported: ["code"],
					subject_types_supported: ["public"],
					jwks_uri: "/.well-known/jwks.json",
				},
			},
		];
		expect(() => buildDiscoveryDocument(items, OPTS)).toThrow(/endpoints/);
	});

	it("still allows literal URI metadata that is NOT an issuer-relative endpoint (op_policy_uri, service_documentation)", () => {
		// These OIDC metadata fields are absolute external URLs, not issuer-relative
		// endpoints — they legitimately belong in `metadata` and must not be caught
		// by the endpoint-field guard.
		const items: OidcDiscoveryContribution[] = [
			...completeItems(),
			{
				metadata: {
					op_policy_uri: "https://op.example/policy",
					service_documentation: "https://op.example/docs",
				},
			},
		];
		const doc = buildDiscoveryDocument(items, OPTS);
		expect(doc.op_policy_uri).toBe("https://op.example/policy");
		expect(doc.service_documentation).toBe("https://op.example/docs");
	});

	it("rejects a metadata field whose VALUE looks issuer-relative (string beginning with '/')", () => {
		// `check_session_iframe` is an issuer-relative OIDC endpoint that does NOT
		// end in `_endpoint`. Contributed via `metadata` it would be emitted
		// origin-less; the value-shape guard ("/"-prefixed string) catches it
		// regardless of field name — belt-and-suspenders with the name-based check.
		const items: OidcDiscoveryContribution[] = [
			...completeItems(),
			{ metadata: { check_session_iframe: "/connect/session" } },
		];
		expect(() => buildDiscoveryDocument(items, OPTS)).toThrow(/issuer-relative|endpoints/);
	});

	it("throws when a required array field is present but empty (validity, not just presence)", () => {
		// `response_types_supported: []` is present (passes the REQUIRED_FIELDS
		// presence check) but OIDC-invalid — an RP cannot use it. Fail fast.
		const items: OidcDiscoveryContribution[] = [
			{
				endpoints: {
					authorization_endpoint: "/oauth/authorize",
					token_endpoint: "/oauth/token",
					jwks_uri: "/.well-known/jwks.json",
				},
				metadata: { response_types_supported: [], subject_types_supported: ["public"] },
			},
		];
		expect(() => buildDiscoveryDocument(items, OPTS)).toThrow(/non-empty array/);
	});
});
