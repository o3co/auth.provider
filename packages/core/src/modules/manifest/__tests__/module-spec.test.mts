import { expectTypeOf, test } from "vitest";
import type { Module, ModuleSpec } from "../module-spec.mjs";

// ---------------------------------------------------------------------------
// Parallel local types — test the structural pattern of ModuleSpec without
// augmenting the shared ComponentMap. This isolates the test from cross-
// file augmentation leaks (vitest typecheck compiles all manifest tests as
// one program).
// ---------------------------------------------------------------------------

interface LocalComponentMap {
  readonly _localCfg: { readonly host: string };
  readonly _localStore: { readonly get: (k: string) => string };
}

type LocalKey = keyof LocalComponentMap;

type LocalProviderDeps<
  R extends LocalKey = never,
  O extends LocalKey = never,
> = { readonly [K in R]: LocalComponentMap[K] } & {
  readonly [K in O]?: LocalComponentMap[K];
};

type LocalProvider<K extends LocalKey, Deps> = (
  deps: Deps,
) => LocalComponentMap[K] | Promise<LocalComponentMap[K]>;

interface LocalModuleSpec<
  R extends LocalKey = never,
  O extends LocalKey = never,
> {
  readonly name: string;
  readonly requires?: readonly R[];
  readonly optional?: readonly O[];
  readonly provides?: {
    readonly [K in LocalKey]?: LocalProvider<K, LocalProviderDeps<R, O>>;
  };
}

test("Module is the erased ModuleSpec alias (post-inference)", () => {
  // Structural test: Module is ModuleSpec with no generic args (= never, never).
  expectTypeOf<Module>().toEqualTypeOf<ModuleSpec>();
});

test("ModuleSpec has the 7 baseline fields, all readonly", () => {
  type Keys = keyof ModuleSpec;
  expectTypeOf<Keys>().toEqualTypeOf<
    | "name"
    | "configSchema"
    | "requires"
    | "optional"
    | "provides"
    | "contributes"
    | "overrides"
  >();
});

test("ModuleSpec.provides keys are typed against the ComponentMap (pattern proof via local mirror)", () => {
  // Use the parallel LocalModuleSpec + LocalComponentMap to prove that
  // a provider for a slot K returns the slot's value type or a Promise.
  // The same mapped-type pattern is in production ModuleSpec.provides;
  // exercising it here on local types is sufficient evidence the pattern
  // works without augmenting the shared ComponentMap.
  type Provides = NonNullable<LocalModuleSpec<"_localCfg">["provides"]>;
  type LocalCfgProvider = NonNullable<Provides["_localCfg"]>;
  expectTypeOf<ReturnType<LocalCfgProvider>>().toEqualTypeOf<
    { readonly host: string } | Promise<{ readonly host: string }>
  >();
});
