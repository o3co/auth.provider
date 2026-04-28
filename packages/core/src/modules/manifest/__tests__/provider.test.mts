import { expectTypeOf, test } from "vitest";
import type { Provider, ProviderDeps } from "../provider.mjs";

// Augment ComponentMap locally for this test file's type-derivation purposes.
declare module "../component-map.mjs" {
  interface ComponentMap {
    readonly _testConfig: { readonly host: string };
    readonly _testLogger: { readonly debug: (m: string) => void };
    readonly _testStore: { readonly get: (k: string) => string };
  }
}

test("ProviderDeps<R, O> derives required + optional shape", () => {
  type Deps = ProviderDeps<"_testConfig" | "_testStore", "_testLogger">;
  expectTypeOf<Deps>().toEqualTypeOf<{
    readonly _testConfig: { readonly host: string };
    readonly _testStore: { readonly get: (k: string) => string };
    readonly _testLogger?: { readonly debug: (m: string) => void };
  }>();
});

test("ProviderDeps<never, never> is an empty object", () => {
  expectTypeOf<ProviderDeps<never, never>>().toEqualTypeOf<{}>();
});

test("Provider<K, Deps> is a function from Deps to ComponentMap[K] | Promise", () => {
  type ConfigProvider = Provider<"_testConfig", ProviderDeps<never, never>>;
  // The provider's return type is the slot's type or a Promise of it.
  expectTypeOf<ConfigProvider>().toMatchTypeOf<
    (deps: {}) => { readonly host: string } | Promise<{ readonly host: string }>
  >();
});
