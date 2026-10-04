import { describe, expect, expectTypeOf, test } from "vitest";
import type { RateLimitSpec } from "../../../ratelimit/types.mjs";
import type { ComponentMap } from "../component-map.mjs";
import type {
	ExchangeTokenValidator,
	FederationProvider,
	GrantHandler,
	MfaFactor,
} from "../contributes-map.mjs";
import {
	type GrantHandlerResolver,
	type MfaFactorResolver,
	type RateLimitBudgetResolver,
	SYNTHETIC_COMPONENT_KEYS,
	type TokenExchangeValidatorResolver,
} from "../synthetic-keys.mjs";

describe("SYNTHETIC_COMPONENT_KEYS", () => {
	test("contains exactly the 11 synthetic keys", () => {
		// mfaFactorResolver comes from the MFA ADR's D3, and
		// sessionRequirementResolver from the session-admission ADR's D3.
		expect(SYNTHETIC_COMPONENT_KEYS.size).toBe(11);
		expect(SYNTHETIC_COMPONENT_KEYS.has("federationProviders")).toBe(true);
		expect(SYNTHETIC_COMPONENT_KEYS.has("tokenExchangeValidatorResolver")).toBe(true);
		expect(SYNTHETIC_COMPONENT_KEYS.has("grantHandlerResolver")).toBe(true);
		expect(SYNTHETIC_COMPONENT_KEYS.has("federationRedirectPolicyResolver")).toBe(true);
		expect(SYNTHETIC_COMPONENT_KEYS.has("lifecycleRegistrar")).toBe(true);
		expect(SYNTHETIC_COMPONENT_KEYS.has("readinessRegistrar")).toBe(true);
		expect(SYNTHETIC_COMPONENT_KEYS.has("mfaFactorResolver")).toBe(true);
		expect(SYNTHETIC_COMPONENT_KEYS.has("sessionRequirementResolver")).toBe(true);
		expect(SYNTHETIC_COMPONENT_KEYS.has("rateLimitBudgetResolver")).toBe(true);
		expect(SYNTHETIC_COMPONENT_KEYS.has("deploymentMode")).toBe(true);
		expect(SYNTHETIC_COMPONENT_KEYS.has("tokenBindingSettings")).toBe(true);
	});

	test("is frozen via Object.freeze (own-property additions blocked)", () => {
		// Object.freeze prevents NEW OWN PROPERTIES from being added to the
		// Set object. It does NOT prevent Set.prototype.add() from mutating
		// the internal [[SetData]] slot — that is a JS engine reality (see
		// the doc comment in synthetic-keys.mts). The PRIMARY immutability
		// guard is the TypeScript ReadonlySet<string> declared type.
		expect(Object.isFrozen(SYNTHETIC_COMPONENT_KEYS)).toBe(true);

		// Adding a property that is NOT a Set internal-slot operation does
		// throw in strict mode (`assignment to read only object`).
		expect(() => {
			// biome-ignore lint/suspicious/noExplicitAny: testing freeze behaviour
			(SYNTHETIC_COMPONENT_KEYS as any).extraProp = "value";
		}).toThrow();
	});

	test("is typed as ReadonlySet<string> (Theme D)", () => {
		expectTypeOf(SYNTHETIC_COMPONENT_KEYS).toEqualTypeOf<ReadonlySet<string>>();
	});
});

describe("GrantHandlerResolver", () => {
	test("has read-only get and entries methods", () => {
		expectTypeOf<GrantHandlerResolver>().toEqualTypeOf<{
			readonly get: (grantType: string) => GrantHandler | undefined;
			readonly entries: () => IterableIterator<readonly [string, GrantHandler]>;
		}>();
	});
});

describe("TokenExchangeValidatorResolver", () => {
	test("has read-only get and entries methods", () => {
		expectTypeOf<TokenExchangeValidatorResolver>().toEqualTypeOf<{
			readonly get: (tokenType: string) => ExchangeTokenValidator | undefined;
			readonly entries: () => IterableIterator<readonly [string, ExchangeTokenValidator]>;
		}>();
	});
});

describe("MfaFactorResolver", () => {
	test("has read-only get and entries methods", () => {
		expectTypeOf<MfaFactorResolver>().toEqualTypeOf<{
			readonly get: (kind: string) => MfaFactor | undefined;
			readonly entries: () => IterableIterator<readonly [string, MfaFactor]>;
		}>();
	});
});

describe("ComponentMap synthetic-resolver slots (declaration-merge)", () => {
	// Without these slots on ComponentMap, downstream modules cannot
	// `requires: ["grantHandlerResolver"]` etc. through the typed
	// defineModule surface (ComponentKey = keyof ComponentMap would not
	// include the synthetic keys). The boot planner injects these
	// projections at applyContributions step 0, so authoring must be able
	// to reference them.
	test("grantHandlerResolver slot is GrantHandlerResolver | undefined", () => {
		expectTypeOf<ComponentMap["grantHandlerResolver"]>().toEqualTypeOf<
			GrantHandlerResolver | undefined
		>();
	});

	test("tokenExchangeValidatorResolver slot is TokenExchangeValidatorResolver | undefined", () => {
		expectTypeOf<ComponentMap["tokenExchangeValidatorResolver"]>().toEqualTypeOf<
			TokenExchangeValidatorResolver | undefined
		>();
	});

	test("federationProviders slot is ReadonlyMap<string, FederationProvider> | undefined", () => {
		expectTypeOf<ComponentMap["federationProviders"]>().toEqualTypeOf<
			ReadonlyMap<string, FederationProvider> | undefined
		>();
	});
});

describe("RateLimitBudgetResolver", () => {
	test("has read-only get and entries methods, over the budgets by prefix", () => {
		expectTypeOf<RateLimitBudgetResolver>().toEqualTypeOf<{
			readonly get: (prefix: string) => RateLimitSpec | undefined;
			readonly entries: () => IterableIterator<readonly [string, RateLimitSpec]>;
		}>();
	});
});
