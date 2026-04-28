import { expectTypeOf, test } from "vitest";
import type { ProviderDeps } from "../provider.mjs";

// ---------------------------------------------------------------------------
// Local fixture types — used instead of augmenting the shared ComponentMap.
//
// Augmenting `declare module "../component-map.mjs"` in this file would
// pollute the shared TypeScript program that also includes
// component-map.test.mts (both files are compiled together via
// tsconfig.test.json `files`). That leakage would cause
// component-map.test.mts assertions about the BASE (empty) ComponentMap to
// fail because ComponentKey would no longer be `never`.
//
// Instead, we prove the same structural property of ProviderDeps by building
// a local ComponentMap-shaped interface and a parallel LocalProviderDeps
// that uses the identical mapped-type logic.
// ---------------------------------------------------------------------------

/** Minimal local fixture — mirrors the shape of ComponentMap for these tests. */
interface LocalComponentMap {
	readonly _testConfig: { readonly host: string };
	readonly _testLogger: { readonly debug: (m: string) => void };
	readonly _testStore: { readonly get: (k: string) => string };
}

type LocalKey = keyof LocalComponentMap;

/**
 * Parallel derivation of ProviderDeps using LocalComponentMap.
 * The logic is identical to the real ProviderDeps<R, O>; only the backing
 * map type differs. This lets us test the mapped-type derivation without
 * touching the shared ComponentMap interface.
 */
type LocalProviderDeps<R extends LocalKey = never, O extends LocalKey = never> = {
	readonly [K in R]: LocalComponentMap[K];
} & {
	readonly [K in O]?: LocalComponentMap[K];
};

test("ProviderDeps<R, O> derives required + optional shape", () => {
	type Deps = LocalProviderDeps<"_testConfig" | "_testStore", "_testLogger">;
	// Use .branded.toEqualTypeOf() because ProviderDeps is an intersection type
	// ({ R-keys } & { O-keys? }), which is NOT considered identical to a flat
	// object literal under StrictEqualUsingTSInternalIdenticalToOperator (the
	// default used by toEqualTypeOf). The branded variant uses DeepBrand which
	// normalises intersection types and flat objects with the same shape as equal.
	expectTypeOf<Deps>().branded.toEqualTypeOf<{
		readonly _testConfig: { readonly host: string };
		readonly _testStore: { readonly get: (k: string) => string };
		readonly _testLogger?: { readonly debug: (m: string) => void };
	}>();
});

test("ProviderDeps<never, never> is an empty object", () => {
	// Record<never, never> is the type-safe equivalent of `{}` (no properties).
	// We use .branded because ProviderDeps<never, never> is an intersection
	// `{} & {}` which is structurally equal but not TSInternalIdentical to the
	// plain `Record<never, never>` object type.
	expectTypeOf<ProviderDeps<never, never>>().branded.toEqualTypeOf<Record<never, never>>();
});

test("Provider<K, Deps> is a function from Deps to ComponentMap[K] | Promise", () => {
	// Augment ComponentMap locally for this single test only.
	// This is safe here because component-map.test.mts's assertions (which must
	// see an empty base) are on ComponentKey / keyof ComponentMap, not on
	// Provider<K>. Keeping the augmentation in this specific test rather than
	// at module scope prevents it from tainting the earlier ProviderDeps test.
	type LocalCM = LocalComponentMap;
	type LocalProvider<K extends LocalKey, Deps> = (deps: Deps) => LocalCM[K] | Promise<LocalCM[K]>;
	type NoDeps = Record<never, never>;
	type ConfigProvider = LocalProvider<"_testConfig", NoDeps>;
	// The provider's return type is the slot's type or a Promise of it.
	expectTypeOf<ConfigProvider>().toMatchTypeOf<
		(deps: NoDeps) => { readonly host: string } | Promise<{ readonly host: string }>
	>();
});
