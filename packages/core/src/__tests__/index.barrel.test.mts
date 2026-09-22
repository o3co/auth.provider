import { describe, expect, it } from "vitest";
import * as core from "../index.mjs";

describe("core barrel — Wave 1 AccessTokenDenylist exports", () => {
	it("re-exports createMemoryAccessTokenDenylist", () => {
		expect(typeof core.createMemoryAccessTokenDenylist).toBe("function");
	});
	it("re-exports createAccessTokenDenylistFactory", () => {
		expect(typeof core.createAccessTokenDenylistFactory).toBe("function");
	});
	it("re-exports registerBuiltinAccessTokenDenylists", () => {
		expect(typeof core.registerBuiltinAccessTokenDenylists).toBe("function");
	});
	it("re-exports memoryAccessTokenDenylistModule", () => {
		expect(core.memoryAccessTokenDenylistModule).toBeDefined();
		expect(typeof core.memoryAccessTokenDenylistModule).toBe("object");
	});
});

describe("core barrel — #282 signing defaults and secret entropy floor", () => {
	it("re-exports DEFAULT_SIGNING_ALGORITHM as an asymmetric algorithm", () => {
		// A composition root that hand-builds its keystore config reads this
		// rather than restating "EdDSA" and drifting from reference.conf.
		expect(core.DEFAULT_SIGNING_ALGORITHM).toBe("EdDSA");
		expect(core.DEFAULT_SIGNING_ALGORITHM).not.toBe("HS256");
	});

	it("re-exports the entropy floor helpers so consumers can apply the same check", () => {
		expect(core.MIN_SECRET_ENTROPY_BYTES).toBe(32);
		expect(typeof core.measureSecretEntropyBytes).toBe("function");
		expect(typeof core.assertSecretEntropy).toBe("function");
		expect(typeof core.describeWeakSecret).toBe("function");
	});
});

describe("core barrel — #593 federation grant domain rules", () => {
	it("re-exports the rules a store adapter, the routes and an integrator all have to agree on", () => {
		expect(core.FEDERATION_GRANT_LIFETIME_CEILING_MS).toBe(31_536_000_000);
		for (const name of [
			"resolveFederationGrantLifetimeMs",
			"federationGrantExpiresAt",
			"withinFederationGrantLifetimeCeiling",
			"federationGrantEffectiveExpiry",
			"federationGrantExpiryState",
			"federationGrantIdentityRevision",
			"federationGrantAuthorizationRevision",
			"judgeUpstreamAccessToken",
			"isUsableMaxUpstreamAccessTokenLifetime",
			"federationGrantIneligibilityStands",
			"federationGrantIneligibilityRetry",
			"federationGrantRefreshFailureStands",
			"resolveFederationGrantIntentScopes",
			"coveredByRevocationBoundary",
			"effectiveFederationGrantStatus",
			"hasFederationGrantAuthorization",
		] as const) {
			expect(typeof (core as Record<string, unknown>)[name], name).toBe("function");
		}
	});

	it("re-exports the store: the port's companions, the memory adapter, its factory and its module", () => {
		for (const name of [
			"createMemoryFederationGrantStore",
			"createFederationGrantStoreFactory",
			"registerBuiltinFederationGrantStores",
		] as const) {
			expect(typeof (core as Record<string, unknown>)[name], name).toBe("function");
		}
		expect(core.DEFAULT_FEDERATION_GRANT_TOMBSTONE_RETENTION_MS).toBe(2_592_000_000);
		expect(core.memoryFederationGrantStoreModule.name).toBe("core-federation-grant-store-memory");
	});

	it("re-exports acquisition's second port, its memory adapter, and the one deadline a flow has", () => {
		for (const name of [
			"createMemoryFederationGrantIntentStore",
			"createFederationGrantIntentStoreFactory",
			"registerBuiltinFederationGrantIntentStores",
			"federationGrantConsentExpiry",
		] as const) {
			expect(typeof (core as Record<string, unknown>)[name], name).toBe("function");
		}
		expect(core.FEDERATION_GRANT_FLOW_BUDGET_MS).toBe(600_000);
		expect(core.FEDERATION_GRANT_FIRST_INTENTS_PER_CLIENT_SUBJECT_LIMIT).toBe(16);
		expect(core.memoryFederationGrantIntentStoreModule.name).toBe(
			"core-federation-grant-intent-store-memory",
		);
	});

	it("re-exports the retrieval the package maps to HTTP, and the timing rule it checks at boot", () => {
		expect(typeof core.retrieveFederationGrantToken).toBe("function");
		expect(() =>
			core.assertFederationGrantRetrievalLimits({
				maxExpiresInMs: 7_776_000_000,
				revocationSkewMs: 1_000,
				refreshBufferMs: 30_000,
				ineligibleRetryAfterMs: 300_000,
				refreshFailureBackoffMs: 30_000,
				upstreamTimeoutMs: 10_000,
				upstreamHardTimeoutMs: 25_000,
				refreshLockTtlMs: 28_000,
				lockWaitMs: 5_000,
				persistRetryBudgetMs: 3_000,
			}),
		).toThrow(RangeError);
	});

	it("re-exports the refresh-error classifier both token routes share", () => {
		expect(core.classifyFederationRefreshError(new Error("boom"))).toEqual({
			reason: "unknown",
			structured: false,
		});
	});

	it("says FederationGrant in every name: this barrel already exports GrantContext and GrantResult for OAuth grant types", () => {
		const generic = [
			"effectiveExpiry",
			"expiryState",
			"identityRevision",
			"authorizationRevision",
			"resolveIntentScopes",
			"effectiveGrantStatus",
			"scopesWithin",
			"createMemoryGrantStore",
			"memoryGrantStoreModule",
		];
		for (const name of generic) {
			expect((core as Record<string, unknown>)[name], name).toBeUndefined();
		}
	});
});
