import { describe, expect, expectTypeOf, test } from "vitest";
import {
  SYNTHETIC_COMPONENT_KEYS,
  type GrantHandlerResolver,
  type TokenExchangeValidatorResolver,
} from "../synthetic-keys.mjs";
import type {
  ExchangeTokenValidator,
  GrantHandler,
} from "../contributes-map.mjs";

describe("SYNTHETIC_COMPONENT_KEYS", () => {
  test("contains exactly the v0.5.0 baseline 3 synthetic keys", () => {
    // Per A2-α §6.5: 3 baseline keys at v0.5.0. A5 (Phase 7) adds a
    // 4th (federationRedirectPolicyResolver). Phase 1 ships the 3.
    expect(SYNTHETIC_COMPONENT_KEYS.size).toBe(3);
    expect(SYNTHETIC_COMPONENT_KEYS.has("federationProviders")).toBe(true);
    expect(SYNTHETIC_COMPONENT_KEYS.has("tokenExchangeValidatorResolver")).toBe(
      true,
    );
    expect(SYNTHETIC_COMPONENT_KEYS.has("grantHandlerResolver")).toBe(true);
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
      readonly entries: () => IterableIterator<
        readonly [string, GrantHandler]
      >;
    }>();
  });
});

describe("TokenExchangeValidatorResolver", () => {
  test("has read-only get and entries methods", () => {
    expectTypeOf<TokenExchangeValidatorResolver>().toEqualTypeOf<{
      readonly get: (
        tokenType: string,
      ) => ExchangeTokenValidator | undefined;
      readonly entries: () => IterableIterator<
        readonly [string, ExchangeTokenValidator]
      >;
    }>();
  });
});
