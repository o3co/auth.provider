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
 * oauth's `discoveryMetadata` contribution: the issuer-RELATIVE endpoints and
 * literal metadata oauth owns. Core's `assembleApp` aggregates every module's
 * contribution into `/.well-known/openid-configuration`, prefixing the issuer
 * and owning `issuer` + `id_token_signing_alg_values_supported`, which oauth
 * never contributes.
 */

import type { AppConfig, OidcDiscoveryContribution } from "@o3co/auth-provider-core";
import {
	createTestFederationSettings,
	makeValidAppConfig,
	resolverForTests,
} from "@o3co/auth-provider-core/testing";
import { describe, expect, it } from "vitest";
import { oauthEndpointsModule } from "../module.mjs";

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
 * Minimal `GrantHandlerResolver` stand-in over the named grant types: `get`
 * answers whether one is registered, `entries` lists them, as the resolver
 * the boot planner builds does.
 */
function grantResolver(...grantTypes: readonly string[]) {
	const handlers = new Map(grantTypes.map((t) => [t, {}]));
	return {
		get: (grantType: string) => handlers.get(grantType),
		entries: () => handlers.entries(),
	};
}

/**
 * Build a config carrying an explicit `oauth.revocation.accessToken`, or
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

async function discoveryContribution(
	deps: Record<string, unknown> = {},
	config: AppConfig = configWithRevocation(),
): Promise<OidcDiscoveryContribution> {
	const factory = oauthEndpointsModule.contributes?.discoveryMetadata?.[0];
	if (factory === undefined) throw new Error("oauthModule contributes no discoveryMetadata");
	// Awaited as the boot planner does: a contribution factory may answer with
	// a promise.
	return await factory({
		// The module's own section, as boot hands it: what the slice reads of
		// `oauth {}`.
		section: config.oauth,
		// Core's view of `core.federations`: none declared unless a test says so.
		federationSettings: createTestFederationSettings(),
		// An authorization server that serves /authorize unless a test says
		// otherwise.
		grantHandlerResolver: grantResolver("authorization_code"),
		sessionRequirementResolver: resolverForTests([]),
		...deps,
	} as never);
}

describe("oauthModule — discoveryMetadata contribution", () => {
	it("declares itself the provider root so core activates discovery", async () => {
		// oauth owns the authorization-server surface, so it sets `providerRoot`.
		// This is the explicit signal (not an inferred `authorization_endpoint`)
		// that core uses to decide whether to synthesize the discovery document.
		expect((await discoveryContribution()).providerRoot).toBe(true);
	});

	it("contributes issuer-relative OAuth endpoints (aggregator prefixes the issuer)", async () => {
		const meta = await discoveryContribution();
		expect(meta.endpoints?.authorization_endpoint).toBe("/oauth/authorize");
		expect(meta.endpoints?.token_endpoint).toBe("/oauth/token");
		expect(meta.endpoints?.userinfo_endpoint).toBe("/oauth/userinfo");
		expect(meta.endpoints?.introspection_endpoint).toBe("/oauth/introspect");
	});

	it("contributes the literal capability metadata", async () => {
		// `private_key_jwt` travels with the replay store that makes it
		// honourable, so the wired composition is what states the full set.
		const meta = await discoveryContribution({ replaySeenSet: {} });
		expect(meta.metadata?.response_types_supported).toEqual(["code"]);
		expect(meta.metadata?.subject_types_supported).toEqual(["public"]);
		expect(meta.metadata?.scopes_supported).toEqual(["openid", "profile", "email", "groups"]);
		expect(meta.metadata?.token_endpoint_auth_methods_supported).toEqual(
			expect.arrayContaining([
				"client_secret_basic",
				"client_secret_post",
				"private_key_jwt",
				"none",
			]),
		);
		// The assertion algorithms travel with the method, and never a
		// symmetric one — a shared secret is what private_key_jwt exists to avoid.
		expect(meta.metadata?.token_endpoint_auth_signing_alg_values_supported).toEqual(
			expect.arrayContaining(["ES256", "RS256", "EdDSA"]),
		);
		expect(meta.metadata?.token_endpoint_auth_signing_alg_values_supported).not.toContain("HS256");
		expect(meta.metadata?.introspection_endpoint_auth_methods_supported).toContain(
			"private_key_jwt",
		);
	});

	it("never contributes the aggregator-owned reserved fields", async () => {
		const meta = await discoveryContribution(allLogoutStores);
		const all = { ...(meta.endpoints ?? {}), ...(meta.metadata ?? {}) };
		expect(all).not.toHaveProperty("issuer");
		expect(all).not.toHaveProperty("id_token_signing_alg_values_supported");
	});

	// -------------------------------------------------------------------------
	// PKCE methods
	// -------------------------------------------------------------------------

	it("advertises S256 only — `plain` is never a server-wide capability", async () => {
		// `code_challenge_methods_supported` is a SERVER-WIDE array (RFC 8414 §2 /
		// RFC 7636 §4.4): a client reading it concludes "I may use any of these".
		// The AS requires S256 of every authorization-code client and no
		// server-wide setting admits `plain`; the only way `plain` is reachable
		// is a registration carrying `allowPlainPkce: true`. That is a named
		// per-client exception, so it stays out of a server-wide array.
		expect((await discoveryContribution()).metadata?.code_challenge_methods_supported).toEqual([
			"S256",
		]);
	});

	it("does not widen code_challenge_methods_supported from any pkce config block", async () => {
		// No configuration shapes the PKCE policy (boot refuses the removed
		// `oauth.grants.authorization_code.pkce` block), and discovery reads
		// none: a configuration handed here carrying one advertises exactly what
		// the AS enforces, which is S256.
		const base = makeValidAppConfig();
		const config = {
			...base,
			oauth: {
				...base.oauth,
				grants: { authorization_code: { pkce: { supportedMethods: ["S256", "plain"] } } },
			},
		} as unknown as AppConfig;
		const factory = oauthEndpointsModule.contributes?.discoveryMetadata?.[0];
		if (factory === undefined) throw new Error("oauthModule contributes no discoveryMetadata");
		const meta = await factory({
			config,
			section: config.oauth,
			grantHandlerResolver: grantResolver("authorization_code"),
			sessionRequirementResolver: resolverForTests([]),
		} as never);
		expect(meta.metadata?.code_challenge_methods_supported).toEqual(["S256"]);
	});

	// -------------------------------------------------------------------------
	// grant_types_supported
	// -------------------------------------------------------------------------

	it("derives grant_types_supported from the grant handlers actually registered", async () => {
		// RFC 8414 §2: an OMITTED `grant_types_supported` defaults to
		// `["authorization_code", "implicit"]`, so saying nothing would advertise
		// an `implicit` flow this AS does not implement. The value is read off the
		// dispatch table `/oauth/token` resolves against, so it cannot drift from
		// what a request would actually reach.
		const meta = await discoveryContribution({
			grantHandlerResolver: grantResolver("authorization_code", "refresh_token"),
		});
		expect(meta.metadata?.grant_types_supported).toEqual(["authorization_code", "refresh_token"]);
	});

	it("never advertises implicit, and reflects config-gated grants exactly", async () => {
		const meta = await discoveryContribution({
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

	it("emits an empty grant_types_supported rather than omitting it when no grant is registered", async () => {
		// Empty is the honest answer for a composition that registered no grant
		// module: every `grant_type` gets `unsupported_grant_type`. Omitting the
		// field would instead assert `authorization_code` + `implicit` support.
		const meta = await discoveryContribution({ grantHandlerResolver: grantResolver() });
		expect(meta.metadata?.grant_types_supported).toEqual([]);
	});

	// -------------------------------------------------------------------------
	// revocation endpoint
	// -------------------------------------------------------------------------

	it("advertises revocation_endpoint when a revocation capability is wired", async () => {
		// `POST /oauth/revoke` is mounted unconditionally by `createOAuthRouter`;
		// withholding it would hide a working endpoint from exactly the clients
		// that discover correctly. `private_key_jwt` is in the set because the
		// store that records an assertion's `jti` is wired.
		const meta = await discoveryContribution({ ...allLogoutStores, replaySeenSet: {} });
		expect(meta.endpoints?.revocation_endpoint).toBe("/oauth/revoke");
		expect(meta.metadata?.revocation_endpoint_auth_methods_supported).toEqual([
			"client_secret_basic",
			"client_secret_post",
			"private_key_jwt",
			"none",
		]);
	});

	// The gate is "can this endpoint revoke ANYTHING", and the two arms of that
	// question resolve differently. The refresh arm is pure wiring. The access
	// arm is wiring AND the declaration: `oauth.revocation.accessToken =
	// "unsupported"` turns the access path off even with a denylist present,
	// because `createRevokeRouter` honours the declaration over the wiring.
	// These five cases are the whole truth table.

	it("advertises when the denylist is wired and the mode is undeclared (read as denylist)", async () => {
		// Both consuming layers — core's boot validator and `createRevokeRouter`
		// — read an undeclared mode as `"denylist"` when a denylist is present.
		// Discovery must agree.
		const meta = await discoveryContribution({ accessTokenDenylist: {} }, configWithRevocation());
		expect(meta.endpoints?.revocation_endpoint).toBe("/oauth/revoke");
	});

	it("advertises when the denylist is wired and the mode is explicitly denylist", async () => {
		const meta = await discoveryContribution(
			{ accessTokenDenylist: {} },
			configWithRevocation("denylist"),
		);
		expect(meta.endpoints?.revocation_endpoint).toBe("/oauth/revoke");
	});

	it("advertises on a refresh-token-only capability (no denylist at all)", async () => {
		// RFC 7009 §2.2.1 defines `unsupported_token_type` precisely so an AS can
		// revoke one token type and not the other. An AS that revokes refresh
		// tokens HAS a revocation endpoint, and the client most in need of it —
		// one revoking an RT on logout — must be able to find it.
		const meta = await discoveryContribution(
			{ refreshTokenFamilyRevocation: {} },
			configWithRevocation("unsupported"),
		);
		expect(meta.endpoints?.revocation_endpoint).toBe("/oauth/revoke");
	});

	it('omits revocation_endpoint when the denylist is wired but the mode is "unsupported" and nothing else can revoke', async () => {
		// A denylist in the component map is not
		// the capability — `createRevokeRouter` resolves the DECLARATION first
		// (`opts.accessTokenRevocation ?? …`), so `"unsupported"` disables the
		// access path however the composition is wired. With no refresh-token
		// revocation either, the endpoint revokes nothing, and gating on the
		// denylist's mere presence would advertise it anyway.
		const meta = await discoveryContribution(
			{ accessTokenDenylist: {} },
			configWithRevocation("unsupported"),
		);
		const all = { ...(meta.endpoints ?? {}), ...(meta.metadata ?? {}) };
		expect(all).not.toHaveProperty("revocation_endpoint");
		expect(all).not.toHaveProperty("revocation_endpoint_auth_methods_supported");
	});

	it("omits revocation_endpoint when nothing behind it can revoke anything", async () => {
		// No `refreshTokenFamilyRevocation` and no `accessTokenDenylist`: the
		// route still answers RFC 7009's mandatory 200, and that 200 means
		// nothing. Advertising it would promise revocation where there is none.
		const meta = await discoveryContribution();
		const all = { ...(meta.endpoints ?? {}), ...(meta.metadata ?? {}) };
		expect(all).not.toHaveProperty("revocation_endpoint");
		expect(all).not.toHaveProperty("revocation_endpoint_auth_methods_supported");
	});

	it("advertises the introspection endpoint's real auth methods (public clients refused)", async () => {
		// RFC 8414 §2: omitted means `["client_secret_basic"]`, which understates
		// `/oauth/introspect`. `none` is absent on purpose — RFC 7662 §2.1, and
		// the route builds its client-auth middleware without
		// `allowPublicClients`.
		const meta = await discoveryContribution({ ...allLogoutStores, replaySeenSet: {} });
		expect(meta.metadata?.introspection_endpoint_auth_methods_supported).toEqual([
			"client_secret_basic",
			"client_secret_post",
			"private_key_jwt",
		]);
	});

	it("advertises end_session_endpoint + logout capabilities when all session stores are present", async () => {
		const meta = await discoveryContribution(allLogoutStores);
		expect(meta.endpoints?.end_session_endpoint).toBe("/oauth/logout");
		expect(meta.metadata?.backchannel_logout_supported).toBe(true);
		expect(meta.metadata?.backchannel_logout_session_supported).toBe(true);
		expect(meta.metadata?.frontchannel_logout_supported).toBe(true);
		expect(meta.metadata?.frontchannel_logout_session_supported).toBe(true);
	});

	it("omits all logout fields when session stores are absent", async () => {
		const meta = await discoveryContribution();
		const all = { ...(meta.endpoints ?? {}), ...(meta.metadata ?? {}) };
		expect(all).not.toHaveProperty("end_session_endpoint");
		expect(all).not.toHaveProperty("backchannel_logout_supported");
		expect(all).not.toHaveProperty("backchannel_logout_session_supported");
		expect(all).not.toHaveProperty("frontchannel_logout_supported");
		expect(all).not.toHaveProperty("frontchannel_logout_session_supported");
	});
});

describe("acr_values_supported", () => {
	const withAcr = (acrValues: Record<string, unknown> | undefined): AppConfig => {
		const base = configWithRevocation();
		return {
			...base,
			oauth: { ...base.oauth, authorize: acrValues ? { acrValues } : {} },
		} as unknown as AppConfig;
	};

	it("advertises the keys of the configured acr table that something installed can satisfy", async () => {
		const meta = await discoveryContribution(
			{},
			withAcr({ "urn:example:pwd": ["pwd"], "urn:example:pwd-any": [["pwd"], ["hwk"]] }),
		);
		expect(meta.metadata?.acr_values_supported).toEqual(["urn:example:pwd", "urn:example:pwd-any"]);
	});

	it("withholds an entry needing fed while no federation is installed: nothing records fed", async () => {
		const meta = await discoveryContribution(
			{},
			withAcr({ "urn:example:pwd": ["pwd"], "urn:example:fed": [["fed"]] }),
		);
		expect(meta.metadata?.acr_values_supported).toEqual(["urn:example:pwd"]);
	});

	it("withholds an entry needing fed when the federations map is empty", async () => {
		const meta = await discoveryContribution(
			{ federationProviders: new Map() },
			withAcr({ "urn:example:pwd": ["pwd"], "urn:example:fed": [["fed"]] }),
		);
		expect(meta.metadata?.acr_values_supported).toEqual(["urn:example:pwd"]);
	});

	it("withholds an entry nothing installed can satisfy", async () => {
		// No login this composition can perform records `mfa` or `hwk`: an RP
		// told it may ask for them would be answered unmet every time.
		const meta = await discoveryContribution(
			{},
			withAcr({
				"urn:example:pwd": ["pwd"],
				"urn:example:mfa": ["pwd", "mfa"],
				"urn:example:phr": [["hwk"], ["swk"]],
			}),
		);
		expect(meta.metadata?.acr_values_supported).toEqual(["urn:example:pwd"]);
	});

	it("advertises an entry a registered requirement's reach can meet", async () => {
		// The union of every requirement's reach is what a step-up can add;
		// `otp` and `mfa` through the second-factor authority, so its entry is
		// advertised, while `phr` still needs a key nothing reaches.
		const meta = await discoveryContribution(
			{
				sessionRequirementResolver: resolverForTests(
					[
						{
							name: "mfa",
							secondFactorAuthority: true,
							reach: new Set(["otp", "mfa"]),
							stepUpPage: { url: "/mfa", params: {} },
							remediations: ["mfa.step_up"],
							hintKeys: [],
							admit: async () => ({ outcome: "met" }),
						},
					],
					{ issuer: "https://issuer.example" },
				),
			},
			withAcr({
				"urn:example:pwd": ["pwd"],
				"urn:example:mfa": ["pwd", "mfa"],
				"urn:example:phr": [["hwk"], ["swk"]],
			}),
		);
		expect(meta.metadata?.acr_values_supported).toEqual(["urn:example:pwd", "urn:example:mfa"]);
	});

	it("says nothing when every entry is withheld", async () => {
		const meta = await discoveryContribution({}, withAcr({ "urn:example:mfa": ["pwd", "mfa"] }));
		expect(meta.metadata).not.toHaveProperty("acr_values_supported");
	});

	it("keeps claims_parameter_supported absent: only its acr use is refused, the rest ignored", async () => {
		// OIDC Discovery defaults it to false, which is the truth: `/authorize`
		// honours no `claims` request.
		expect((await discoveryContribution()).metadata).not.toHaveProperty(
			"claims_parameter_supported",
		);
	});

	it("withholds an entry only an upstream IdP could meet while no installed federation trusts its amr", async () => {
		// An untrusted IdP's `amr` is kept apart from the session's and counts
		// for no `acr`, so only `fed` itself is what a federation adds.
		const meta = await discoveryContribution(
			{ federationProviders: new Map([["google", {}]]) },
			withAcr({
				"urn:example:pwd": ["pwd"],
				"urn:example:fed": ["fed"],
				"urn:example:phr": [["hwk"], ["swk"]],
			}),
		);
		expect(meta.metadata?.acr_values_supported).toEqual(["urn:example:pwd", "urn:example:fed"]);
	});

	it("advertises every entry while an installed federation trusts its upstream amr: that IdP may assert any value", async () => {
		const config = withAcr({ "urn:example:pwd": ["pwd"], "urn:example:phr": [["hwk"], ["swk"]] });
		const trusting = (trustsUpstreamAmr: boolean) => ({
			federationProviders: new Map([["google", {}]]),
			federationSettings: createTestFederationSettings({
				google: { type: "google", trustsUpstreamAmr },
			}),
		});
		const trusted = await discoveryContribution(trusting(true), config);
		expect(trusted.metadata?.acr_values_supported).toEqual(["urn:example:pwd", "urn:example:phr"]);
		const untrusted = await discoveryContribution(trusting(false), config);
		expect(untrusted.metadata?.acr_values_supported).toEqual(["urn:example:pwd"]);
	});

	it("takes trust from trustsUpstreamAmr alone, which core's view answers false for a disabled entry", async () => {
		// Whether a disabled entry is trusted is core's decision, made when it
		// fills the slot (`trustsUpstreamAmr` is true only beside `enabled`);
		// the module reads the member and nothing else of the entry. The
		// boot-level case in `module.test.mts` holds the decision end to end.
		const meta = await discoveryContribution(
			{
				federationProviders: new Map([["google", {}]]),
				federationSettings: createTestFederationSettings({
					google: { type: "google", enabled: false },
				}),
			},
			withAcr({ "urn:example:pwd": ["pwd"], "urn:example:phr": [["hwk"], ["swk"]] }),
		);
		expect(meta.metadata?.acr_values_supported).toEqual(["urn:example:pwd"]);
	});

	it("does not count a trusted federation that is not installed", async () => {
		// The switch names a configured entry; only an installed federation
		// can write a session.
		const meta = await discoveryContribution(
			{
				federationProviders: new Map(),
				federationSettings: createTestFederationSettings({
					google: { type: "google", trustsUpstreamAmr: true },
				}),
			},
			withAcr({ "urn:example:pwd": ["pwd"], "urn:example:phr": [["hwk"], ["swk"]] }),
		);
		expect(meta.metadata?.acr_values_supported).toEqual(["urn:example:pwd"]);
	});

	it("does not count an installed federation federationSettings holds no entry for", async () => {
		const meta = await discoveryContribution(
			{
				federationProviders: new Map([["google", {}]]),
				federationSettings: createTestFederationSettings({
					other: { type: "google", trustsUpstreamAmr: true },
				}),
			},
			withAcr({ "urn:example:pwd": ["pwd"], "urn:example:phr": [["hwk"], ["swk"]] }),
		);
		expect(meta.metadata?.acr_values_supported).toEqual(["urn:example:pwd"]);
	});

	it("says nothing when there is no table — an acr_values request is then unmet", async () => {
		expect((await discoveryContribution({}, withAcr(undefined))).metadata).not.toHaveProperty(
			"acr_values_supported",
		);
	});
});

describe("oauthModule — client_id_metadata_document_supported", () => {
	const enabled = (): AppConfig => {
		const base = configWithRevocation();
		return {
			...base,
			oauth: { ...base.oauth, clientIdMetadataDocuments: { enabled: true } },
		} as unknown as AppConfig;
	};

	it("advertises Client ID Metadata Documents only when the feature is on", async () => {
		// MCP 2026-07-28: a hosted client selects CIMD when the AS advertises
		// this AND lists `none` in token_endpoint_auth_methods_supported.
		const off = await discoveryContribution({ consentStore: {} });
		expect(off.metadata?.client_id_metadata_document_supported).toBeUndefined();

		const on = await discoveryContribution({ consentStore: {} }, enabled());
		expect(on.metadata?.client_id_metadata_document_supported).toBe(true);
		expect(on.metadata?.token_endpoint_auth_methods_supported).toContain("none");
	});

	it("says nothing without a consent store — a document client could not finish the flow", async () => {
		// Every document client is non-first-party, and `/authorize` refuses
		// those without a consent store. Advertising CIMD there sends an MCP
		// client down a flow this deployment cannot complete.
		const on = await discoveryContribution({}, enabled());
		expect(on.metadata?.client_id_metadata_document_supported).toBeUndefined();
	});

	it("says nothing without the authorization_code grant — a document client can use no other", async () => {
		const on = await discoveryContribution(
			{ consentStore: {}, grantHandlerResolver: grantResolver("client_credentials") },
			enabled(),
		);
		expect(on.metadata?.client_id_metadata_document_supported).toBeUndefined();
	});
});

describe("oauthModule — private_key_jwt is advertised only where it can be honoured", () => {
	it("says nothing about private_key_jwt when no replay seen-set is wired", async () => {
		// A client assertion's `jti` is single-use, and the verifier answers
		// `500 server_error` when it has nowhere to record one rather than
		// authenticating it unchecked. Advertising the method anyway sends a
		// client to three endpoints that will all refuse it — the same "on and
		// completable" rule this file applies to CIMD, logout and revocation.
		const off = await discoveryContribution();
		expect(off.metadata?.token_endpoint_auth_methods_supported).not.toContain("private_key_jwt");
		expect(off.metadata?.token_endpoint_auth_signing_alg_values_supported).toBeUndefined();
		expect(off.metadata?.introspection_endpoint_auth_methods_supported).not.toContain(
			"private_key_jwt",
		);
		expect(off.metadata?.introspection_endpoint_auth_signing_alg_values_supported).toBeUndefined();
	});

	it("still advertises the methods that need no store", async () => {
		const off = await discoveryContribution();
		expect(off.metadata?.token_endpoint_auth_methods_supported).toEqual([
			"client_secret_basic",
			"client_secret_post",
			"none",
		]);
		expect(off.metadata?.introspection_endpoint_auth_methods_supported).toEqual([
			"client_secret_basic",
			"client_secret_post",
		]);
	});

	it("advertises it, with its algorithms, once a store is wired", async () => {
		const on = await discoveryContribution({ replaySeenSet: {} });
		expect(on.metadata?.token_endpoint_auth_methods_supported).toContain("private_key_jwt");
		expect(on.metadata?.token_endpoint_auth_signing_alg_values_supported).toEqual(
			expect.arrayContaining(["ES256", "RS256", "EdDSA"]),
		);
		expect(on.metadata?.introspection_endpoint_auth_methods_supported).toContain("private_key_jwt");
		expect(on.metadata?.introspection_endpoint_auth_signing_alg_values_supported).toEqual(
			expect.arrayContaining(["ES256", "RS256", "EdDSA"]),
		);
	});

	it("gates the revocation entries on the store as well as on revocation being possible", async () => {
		const revoking = { refreshTokenFamilyRevocation: {} };
		const withoutStore = await discoveryContribution(revoking);
		expect(withoutStore.metadata?.revocation_endpoint_auth_methods_supported).not.toContain(
			"private_key_jwt",
		);
		expect(
			withoutStore.metadata?.revocation_endpoint_auth_signing_alg_values_supported,
		).toBeUndefined();

		const withStore = await discoveryContribution({ ...revoking, replaySeenSet: {} });
		expect(withStore.metadata?.revocation_endpoint_auth_methods_supported).toContain(
			"private_key_jwt",
		);
	});
});

describe("a composition with no authorization_code grant", () => {
	const headless = () =>
		discoveryContribution({ grantHandlerResolver: grantResolver("client_credentials") });

	it("names no authorization endpoint and lists no response type", async () => {
		const meta = await headless();
		expect(meta.endpoints).not.toHaveProperty("authorization_endpoint");
		expect(meta.metadata?.response_types_supported).toEqual([]);
		expect(meta.endpoints?.token_endpoint).toBe("/oauth/token");
		expect(meta.metadata?.grant_types_supported).toEqual(["client_credentials"]);
	});

	it("advertises none of the authorization request's parameters", async () => {
		const meta = await headless();
		expect(meta.metadata).not.toHaveProperty("code_challenge_methods_supported");
		expect(meta.metadata).not.toHaveProperty("request_uri_parameter_supported");
		expect(meta.metadata).not.toHaveProperty("authorization_response_iss_parameter_supported");
		expect(meta.metadata).not.toHaveProperty("response_modes_supported");
	});

	it("advertises no acr table: acr_values are asked for at /authorize", async () => {
		const base = configWithRevocation();
		const config = {
			...base,
			oauth: { ...base.oauth, authorize: { acrValues: { "urn:example:pwd": ["pwd"] } } },
		} as unknown as AppConfig;
		const meta = await discoveryContribution(
			{ grantHandlerResolver: grantResolver("client_credentials") },
			config,
		);
		expect(meta.metadata).not.toHaveProperty("acr_values_supported");
	});

	it("with the grant, names /oauth/authorize and the code response type", async () => {
		const meta = await discoveryContribution({
			grantHandlerResolver: grantResolver("authorization_code", "client_credentials"),
		});
		expect(meta.endpoints?.authorization_endpoint).toBe("/oauth/authorize");
		expect(meta.metadata?.response_types_supported).toEqual(["code"]);
		expect(meta.metadata?.code_challenge_methods_supported).toEqual(["S256"]);
	});

	it("with the grant, advertises that every authorization response carries iss (RFC 9207)", async () => {
		const meta = await discoveryContribution({
			grantHandlerResolver: grantResolver("authorization_code"),
		});
		expect(meta.metadata?.authorization_response_iss_parameter_supported).toBe(true);
	});

	it("with the grant, advertises the query response mode alone: /authorize answers in the query", async () => {
		const meta = await discoveryContribution({
			grantHandlerResolver: grantResolver("authorization_code"),
		});
		expect(meta.metadata?.response_modes_supported).toEqual(["query"]);
	});
});
