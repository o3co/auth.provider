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

import type { AppConfig, OidcDiscoveryContribution } from "@o3co/auth-provider-core";
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

/**
 * Minimal `GrantHandlerResolver` stand-in exposing the registered grant-type
 * names. `grant_types_supported` is derived from exactly this read, so the
 * stub only needs to answer `entries()`.
 */
function grantResolver(...grantTypes: readonly string[]) {
	return {
		get: () => undefined,
		entries: () => new Map(grantTypes.map((t) => [t, {}])).entries(),
	};
}

/**
 * Build a config carrying an explicit `oauth.revocation.accessToken` (#277), or
 * the untouched fixture when `mode` is omitted — which is the UNDECLARED case
 * both consuming layers read as `"denylist"`.
 */
function configWithRevocation(mode?: "denylist" | "unsupported"): AppConfig {
	const base = makeValidAppConfig();
	if (mode === undefined) return base as unknown as AppConfig;
	return {
		...base,
		oauth: { ...base.oauth, revocation: { accessToken: mode } },
	} as unknown as AppConfig;
}

function discoveryContribution(
	deps: Record<string, unknown> = {},
	config: AppConfig = configWithRevocation(),
): OidcDiscoveryContribution {
	const factory = oauthModule({ config }).contributes?.discoveryMetadata?.[0];
	if (factory === undefined) throw new Error("oauthModule contributes no discoveryMetadata");
	return factory({ config, grantHandlerResolver: grantResolver(), ...deps } as never);
}

describe("oauthModule — discoveryMetadata contribution", () => {
	it("declares itself the provider root so core activates discovery", () => {
		// oauth owns the authorization-server surface, so it sets `providerRoot`.
		// This is the explicit signal (not an inferred `authorization_endpoint`)
		// that core uses to decide whether to synthesize the discovery document.
		expect(discoveryContribution().providerRoot).toBe(true);
	});

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

	// -------------------------------------------------------------------------
	// #283 — PKCE methods
	// -------------------------------------------------------------------------

	it("advertises S256 only — `plain` is never a server-wide capability", () => {
		// `code_challenge_methods_supported` is a SERVER-WIDE array (RFC 8414 §2 /
		// RFC 7636 §4.4): a client reading it concludes "I may use any of these".
		// Since #273 the AS requires S256 of every authorization-code client and
		// no server-wide setting admits `plain`; the only way `plain` is reachable
		// is a registration carrying `allowPlainPkce: true`. That is a named
		// per-client exception, so it stays out of a server-wide array.
		expect(discoveryContribution().metadata?.code_challenge_methods_supported).toEqual(["S256"]);
	});

	it("does not widen code_challenge_methods_supported from any pkce config block", () => {
		// #273 stopped honouring `oauth.grants.authorization_code.pkce.
		// supportedMethods` at enforcement time. Discovery must not resurrect it
		// as an advertisement either: a config that still carries the key
		// advertises exactly what the AS enforces, which is S256.
		const base = makeValidAppConfig();
		const config = {
			...base,
			oauth: {
				...base.oauth,
				grants: {
					...base.oauth.grants,
					authorization_code: { pkce: { supportedMethods: ["S256", "plain"] } },
				},
			},
		} as unknown as AppConfig;
		const factory = oauthModule({ config }).contributes?.discoveryMetadata?.[0];
		if (factory === undefined) throw new Error("oauthModule contributes no discoveryMetadata");
		const meta = factory({ config, grantHandlerResolver: grantResolver() } as never);
		expect(meta.metadata?.code_challenge_methods_supported).toEqual(["S256"]);
	});

	// -------------------------------------------------------------------------
	// #283 — grant_types_supported
	// -------------------------------------------------------------------------

	it("derives grant_types_supported from the grant handlers actually registered", () => {
		// RFC 8414 §2: an OMITTED `grant_types_supported` defaults to
		// `["authorization_code", "implicit"]`, so saying nothing advertised an
		// `implicit` flow this AS has never implemented. The value is read off the
		// dispatch table `/oauth/token` resolves against, so it cannot drift from
		// what a request would actually reach.
		const meta = discoveryContribution({
			grantHandlerResolver: grantResolver("authorization_code", "refresh_token"),
		});
		expect(meta.metadata?.grant_types_supported).toEqual(["authorization_code", "refresh_token"]);
	});

	it("never advertises implicit, and reflects config-gated grants exactly", () => {
		const meta = discoveryContribution({
			grantHandlerResolver: grantResolver(
				"authorization_code",
				"client_credentials",
				"urn:ietf:params:oauth:grant-type:token-exchange",
			),
		});
		const grantTypes = meta.metadata?.grant_types_supported as readonly string[];
		expect(grantTypes).not.toContain("implicit");
		expect(grantTypes).toContain("client_credentials");
		expect(grantTypes).toContain("urn:ietf:params:oauth:grant-type:token-exchange");
	});

	it("emits an empty grant_types_supported rather than omitting it when no grant is registered", () => {
		// Empty is the honest answer for a composition that registered no grant
		// module: every `grant_type` gets `unsupported_grant_type`. Omitting the
		// field would instead assert `authorization_code` + `implicit` support.
		const meta = discoveryContribution();
		expect(meta.metadata?.grant_types_supported).toEqual([]);
	});

	// -------------------------------------------------------------------------
	// #283 — revocation endpoint
	// -------------------------------------------------------------------------

	it("advertises revocation_endpoint when a revocation capability is wired", () => {
		// Inverts the pre-#283 assertion that `revocation_endpoint` was
		// deliberately withheld. `POST /oauth/revoke` is mounted unconditionally
		// by `createOAuthRouter`, so withholding it hid a working endpoint from
		// exactly the clients that discover correctly.
		const meta = discoveryContribution(allLogoutStores);
		expect(meta.endpoints?.revocation_endpoint).toBe("/oauth/revoke");
		expect(meta.metadata?.revocation_endpoint_auth_methods_supported).toEqual([
			"client_secret_basic",
			"client_secret_post",
			"none",
		]);
	});

	// The gate is "can this endpoint revoke ANYTHING", and the two arms of that
	// question resolve differently. The refresh arm is pure wiring. The access
	// arm is wiring AND the #277 declaration: `oauth.revocation.accessToken =
	// "unsupported"` turns the access path off even with a denylist present,
	// because `createRevokeRouter` honours the declaration over the wiring.
	// These five cases are the whole truth table.

	it("advertises when the denylist is wired and the mode is undeclared (read as denylist)", () => {
		// Undeclared is what every pre-#277 config looks like, and both consuming
		// layers — core's boot validator and `createRevokeRouter` — read it as
		// `"denylist"` when a denylist is present. Discovery must agree.
		const meta = discoveryContribution({ accessTokenDenylist: {} }, configWithRevocation());
		expect(meta.endpoints?.revocation_endpoint).toBe("/oauth/revoke");
	});

	it("advertises when the denylist is wired and the mode is explicitly denylist", () => {
		const meta = discoveryContribution(
			{ accessTokenDenylist: {} },
			configWithRevocation("denylist"),
		);
		expect(meta.endpoints?.revocation_endpoint).toBe("/oauth/revoke");
	});

	it("advertises on a refresh-token-only capability (no denylist at all)", () => {
		// RFC 7009 §2.2.1 defines `unsupported_token_type` precisely so an AS can
		// revoke one token type and not the other. An AS that revokes refresh
		// tokens HAS a revocation endpoint, and the client most in need of it —
		// one revoking an RT on logout — must be able to find it.
		const meta = discoveryContribution(
			{ refreshTokenFamilyRevocation: {} },
			configWithRevocation("unsupported"),
		);
		expect(meta.endpoints?.revocation_endpoint).toBe("/oauth/revoke");
	});

	it('omits revocation_endpoint when the denylist is wired but the mode is "unsupported" and nothing else can revoke', () => {
		// The gap Copilot found on #359. A denylist in the component map is not
		// the capability — `createRevokeRouter` resolves the DECLARATION first
		// (`opts.accessTokenRevocation ?? …`), so `"unsupported"` disables the
		// access path however the composition is wired. With no refresh-token
		// revocation either, the endpoint revokes nothing, and gating on the
		// denylist's mere presence would advertise it anyway.
		const meta = discoveryContribution(
			{ accessTokenDenylist: {} },
			configWithRevocation("unsupported"),
		);
		const all = { ...(meta.endpoints ?? {}), ...(meta.metadata ?? {}) };
		expect(all).not.toHaveProperty("revocation_endpoint");
		expect(all).not.toHaveProperty("revocation_endpoint_auth_methods_supported");
	});

	it("omits revocation_endpoint when nothing behind it can revoke anything", () => {
		// No `refreshTokenFamilyRevocation` and no `accessTokenDenylist`: the
		// route still answers RFC 7009's mandatory 200, and that 200 means
		// nothing. Advertising it would be the #277 failure in metadata form.
		const meta = discoveryContribution();
		const all = { ...(meta.endpoints ?? {}), ...(meta.metadata ?? {}) };
		expect(all).not.toHaveProperty("revocation_endpoint");
		expect(all).not.toHaveProperty("revocation_endpoint_auth_methods_supported");
	});

	it("advertises the introspection endpoint's real auth methods (public clients refused)", () => {
		// RFC 8414 §2: omitted means `["client_secret_basic"]`, which understates
		// `/oauth/introspect`. `none` is absent on purpose — RFC 7662 §2.1, and
		// the route builds its client-auth middleware without
		// `allowPublicClients`.
		const meta = discoveryContribution(allLogoutStores);
		expect(meta.metadata?.introspection_endpoint_auth_methods_supported).toEqual([
			"client_secret_basic",
			"client_secret_post",
		]);
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
