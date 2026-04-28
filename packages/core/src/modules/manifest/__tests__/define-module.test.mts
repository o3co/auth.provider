import { expectTypeOf, test } from "vitest";
import type { ComponentKey } from "../component-map.mjs";
import type { defineModule } from "../define-module.mjs";
import type { Module, ModuleSpec } from "../module-spec.mjs";

// ---------------------------------------------------------------------------
// Parallel local helpers — test defineModule's `const` generic inference
// against a local ComponentMap-shaped fixture. We re-derive a local
// `defineLocalModule` with the SAME shape as the production `defineModule`
// (single `const` generic, mapped-type provides).
//
// The production `defineModule<const R extends ComponentKey, ...>` cannot
// be called with arbitrary keys because ComponentKey resolves to `never`
// in the v0.5.0 baseline (empty ComponentMap). Calling
// `defineModule({ requires: ["foo"] })` would fail with `"foo" not assignable
// to never` — exactly the typecheck protection we want for production code.
//
// To test the INFERENCE behaviour, we mirror the helper locally with a
// non-empty fixture. This proves the pattern works; production-typed
// inference is exercised when real ComponentMap slots land in Phases 5-8.
// ---------------------------------------------------------------------------

interface LocalCM {
	readonly _localCfg: { readonly host: string };
	readonly _localLog: { readonly debug: (m: string) => void };
	readonly _localStore: { readonly get: () => string };
}

type LocalKey = keyof LocalCM;

type LocalProviderDeps<R extends LocalKey = never, O extends LocalKey = never> = {
	readonly [K in R]: LocalCM[K];
} & {
	readonly [K in O]?: LocalCM[K];
};

interface LocalModuleSpec<R extends LocalKey = never, O extends LocalKey = never> {
	readonly name: string;
	readonly requires?: readonly R[];
	readonly optional?: readonly O[];
	readonly provides?: {
		readonly [K in LocalKey]?: (deps: LocalProviderDeps<R, O>) => LocalCM[K] | Promise<LocalCM[K]>;
	};
}

/**
 * The widened "erased" form of LocalModuleSpec — mirrors the production
 * pattern `Module = ModuleSpec<ComponentKey, ComponentKey>` so that
 * `LocalModuleSpec<R, O>` (any subset R, O ⊆ LocalKey) is structurally
 * assignable here without a cast. Without this widening, returning
 * `LocalModuleSpec` (= `LocalModuleSpec<never, never>`) would reject
 * the `const`-inferred narrow type at the function boundary.
 *
 * The same widening was applied to production `Module` in module-spec.mts.
 */
type LocalModule = LocalModuleSpec<LocalKey, LocalKey>;

function defineLocalModule<const R extends LocalKey = never, const O extends LocalKey = never>(
	spec: LocalModuleSpec<R, O>,
): LocalModule {
	return spec;
}

test("defineLocalModule infers requires literal array (no `as const` needed)", () => {
	const m = defineLocalModule({
		name: "test",
		requires: ["_localCfg"],
		provides: {
			_localStore: (deps) => {
				// deps should be typed as LocalProviderDeps<"_localCfg", never>.
				expectTypeOf(deps).toEqualTypeOf<LocalProviderDeps<"_localCfg", never>>();
				return { get: () => deps._localCfg.host };
			},
		},
	});
	expectTypeOf(m).toMatchTypeOf<LocalModule>();
});

test("defineLocalModule infers optional literal array", () => {
	const m = defineLocalModule({
		name: "test",
		requires: ["_localCfg"],
		optional: ["_localLog"],
		provides: {
			_localStore: (deps) => {
				expectTypeOf(deps).toEqualTypeOf<LocalProviderDeps<"_localCfg", "_localLog">>();
				// Optional key access is `T | undefined`.
				expectTypeOf(deps._localLog).toEqualTypeOf<
					{ readonly debug: (m: string) => void } | undefined
				>();
				return { get: () => deps._localCfg.host };
			},
		},
	});
	expectTypeOf(m).toMatchTypeOf<LocalModule>();
});

test("defineLocalModule with no requires/optional uses empty deps", () => {
	const m = defineLocalModule({
		name: "test",
		provides: {
			_localStore: (deps) => {
				// never/never deps = {}
				expectTypeOf(deps).toEqualTypeOf<Record<never, never>>();
				return { get: () => "static" };
			},
		},
	});
	expectTypeOf(m).toMatchTypeOf<LocalModule>();
});

test("production defineModule signature compiles (smoke check)", () => {
	// Pure type-level smoke check — verify the production defineModule
	// is exported with the expected signature shape. We don't call it
	// because ComponentKey = never in the empty-base ComponentMap.
	type DefineModuleType = typeof defineModule;
	expectTypeOf<DefineModuleType>().toMatchTypeOf<
		<const R extends ComponentKey = never, const O extends ComponentKey = never>(
			spec: ModuleSpec<R, O>,
		) => Module
	>();
});
