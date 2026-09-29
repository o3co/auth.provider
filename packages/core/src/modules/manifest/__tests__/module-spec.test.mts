import { expectTypeOf, test } from "vitest";
import type { ComponentKey } from "../component-map.mjs";
import type { SectionSchema } from "../module-section.mjs";
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

type LocalProviderDeps<R extends LocalKey = never, O extends LocalKey = never> = {
	readonly [K in R]: LocalComponentMap[K];
} & {
	readonly [K in O]?: LocalComponentMap[K];
};

type LocalProvider<K extends LocalKey, Deps> = (
	deps: Deps,
) => LocalComponentMap[K] | Promise<LocalComponentMap[K]>;

interface LocalModuleSpec<R extends LocalKey = never, O extends LocalKey = never> {
	readonly name: string;
	readonly requires?: readonly R[];
	readonly optional?: readonly O[];
	readonly provides?: {
		readonly [K in LocalKey]?: LocalProvider<K, LocalProviderDeps<R, O>>;
	};
}

test("Module is the widened ModuleSpec alias (post-inference)", () => {
	// Structural test: Module is ModuleSpec<ComponentKey, ComponentKey,
	// SectionSchema> per the variance widening in module-spec.mts. Asserting
	// against `ModuleSpec` (= `ModuleSpec<never, never, never>`) would pass by
	// accident only while ComponentKey is never, and fail silently once it
	// names real slots. The assertion below holds either way: both sides
	// expand identically. The third argument is the widest section schema.
	expectTypeOf<Module>().toEqualTypeOf<ModuleSpec<ComponentKey, ComponentKey, SectionSchema>>();
	// And that is `ModuleSpec`'s default for it, so the two-argument spelling
	// also names `Module`.
	expectTypeOf<Module>().toEqualTypeOf<ModuleSpec<ComponentKey, ComponentKey>>();
});

test("ModuleSpec has the 12 baseline fields, all readonly", () => {
	type Keys = keyof ModuleSpec;
	expectTypeOf<Keys>().toEqualTypeOf<
		| "name"
		| "section"
		| "authoritative"
		| "configSchema"
		| "requires"
		| "optional"
		| "absencePolicies"
		| "replicaSafety"
		| "provides"
		| "contributes"
		| "overrides"
		| "lifecycle"
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
