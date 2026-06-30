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
 * oauth `discoveryMetadata` contribution.
 *
 * The OIDC discovery document is no longer owned end-to-end by the oauth
 * module; instead oauth contributes the issuer-RELATIVE endpoints + literal
 * metadata it owns, and core's `assembleApp` aggregates every module's
 * `discoveryMetadata` (oauth's endpoints + capabilities, jwks's `jwks_uri`)
 * into the single `/.well-known/openid-configuration` document — prefixing the
 * issuer and owning `issuer` + `id_token_signing_alg_values_supported`.
 *
 * These tests pin oauth's slice of that contract. Endpoint values are
 * issuer-relative paths (the aggregator prefixes the issuer); oauth never
 * contributes the aggregator-owned reserved fields.
 */

import type { AppConfig, DiscoveryMetadata } from "@o3co/auth-provider-core";
import { makeValidAppConfig } from "@o3co/auth-provider-core/testing";
import { describe, expect, it } from "vitest";
import { oauthModule } from "../module.mjs";

/** Truthy stubs for the six session-store deps that gate logout advertisement. */
const allLogoutStores = {
	userSessionStore: {},
	sessionRPRegistry: {},
	sessionFamilyIndex: {},
	sessionFederationIndex: {},
	federationTokenStore: {},
	refreshTokenFamilyRevocation: {},
};

function discoveryContribution(deps: Record<string, unknown> = {}): DiscoveryMetadata {
	const config = makeValidAppConfig() as unknown as AppConfig;
	const factory = oauthModule({ config }).contributes?.discoveryMetadata?.[0];
	if (factory === undefined) throw new Error("oauthModule contributes no discoveryMetadata");
	return factory({ config, ...deps } as never);
}

describe("oauthModule — discoveryMetadata contribution", () => {
	it("contributes issuer-relative OAuth endpoints (aggregator prefixes the issuer)", () => {
		const meta = discoveryContribution();
		expect(meta.endpoints?.authorization_endpoint).toBe("/oauth/authorize");
		expect(meta.endpoints?.token_endpoint).toBe("/oauth/token");
		expect(meta.endpoints?.userinfo_endpoint).toBe("/oauth/userinfo");
		expect(meta.endpoints?.introspection_endpoint).toBe("/oauth/introspect");
	});

	it("contributes the literal capability metadata", () => {
		const meta = discoveryContribution();
		expect(meta.metadata?.response_types_supported).toEqual(["code"]);
		expect(meta.metadata?.subject_types_supported).toEqual(["public"]);
		expect(meta.metadata?.scopes_supported).toEqual(["openid", "profile", "email", "groups"]);
		expect(meta.metadata?.code_challenge_methods_supported).toEqual(["S256"]);
		expect(meta.metadata?.token_endpoint_auth_methods_supported).toEqual(
			expect.arrayContaining(["client_secret_basic", "client_secret_post", "none"]),
		);
	});

	it("never contributes the aggregator-owned reserved fields", () => {
		const meta = discoveryContribution(allLogoutStores);
		const all = { ...(meta.endpoints ?? {}), ...(meta.metadata ?? {}) };
		expect(all).not.toHaveProperty("issuer");
		expect(all).not.toHaveProperty("id_token_signing_alg_values_supported");
	});

	it("does NOT advertise revocation_endpoint (out of scope)", () => {
		const meta = discoveryContribution(allLogoutStores);
		const all = { ...(meta.endpoints ?? {}), ...(meta.metadata ?? {}) };
		expect(all).not.toHaveProperty("revocation_endpoint");
	});

	it("advertises end_session_endpoint + logout capabilities when all session stores are present", () => {
		const meta = discoveryContribution(allLogoutStores);
		expect(meta.endpoints?.end_session_endpoint).toBe("/oauth/logout");
		expect(meta.metadata?.backchannel_logout_supported).toBe(true);
		expect(meta.metadata?.backchannel_logout_session_supported).toBe(true);
		expect(meta.metadata?.frontchannel_logout_supported).toBe(true);
		expect(meta.metadata?.frontchannel_logout_session_supported).toBe(true);
	});

	it("omits all logout fields when session stores are absent", () => {
		const meta = discoveryContribution();
		const all = { ...(meta.endpoints ?? {}), ...(meta.metadata ?? {}) };
		expect(all).not.toHaveProperty("end_session_endpoint");
		expect(all).not.toHaveProperty("backchannel_logout_supported");
		expect(all).not.toHaveProperty("backchannel_logout_session_supported");
		expect(all).not.toHaveProperty("frontchannel_logout_supported");
		expect(all).not.toHaveProperty("frontchannel_logout_session_supported");
	});
});
