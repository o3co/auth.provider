import { expectTypeOf, test } from "vitest";
import { z } from "zod";
import type { ProviderDeps } from "../provider.mjs";

// ---------------------------------------------------------------------------
// Local fixture types, used instead of augmenting the shared ComponentMap:
// this file is compiled in one program with component-map.test.mts
// (tsconfig.test.json `files`), whose assertions about the BASE ComponentMap
// an augmentation here would break.
// ---------------------------------------------------------------------------

/** Minimal local fixture — mirrors the shape of ComponentMap for these tests. */
interface LocalComponentMap {
	readonly _testConfig: { readonly host: string };
	readonly _testLogger: { readonly debug: (m: string) => void };
	readonly _testStore: { readonly get: (k: string) => string };
}

type LocalKey = keyof LocalComponentMap;

/** ProviderDeps<R, O>'s mapped-type logic, over LocalComponentMap. */
type LocalProviderDeps<R extends LocalKey = never, O extends LocalKey = never> = {
	readonly [K in R]: NonNullable<LocalComponentMap[K]>;
} & {
	readonly [K in O]?: LocalComponentMap[K];
};

test("ProviderDeps<R, O> derives required + optional shape", () => {
	type Deps = LocalProviderDeps<"_testConfig" | "_testStore", "_testLogger">;
	// `.branded`: the intersection ({ R-keys } & { O-keys? }) is NOT identical
	// to a flat object literal under toEqualTypeOf's default comparison;
	// DeepBrand treats same-shaped intersections and flat objects as equal.
	expectTypeOf<Deps>().branded.toEqualTypeOf<{
		readonly _testConfig: { readonly host: string };
		readonly _testStore: { readonly get: (k: string) => string };
		readonly _testLogger?: { readonly debug: (m: string) => void };
	}>();
});

test("ProviderDeps strips `| undefined` from required slots derived from optional ComponentMap entries", () => {
	// ComponentMap declares every slot OPTIONAL (`slot?: T`) so slots merge in
	// additively. Required keys must still come out non-undefined, or every
	// `provides` callback would need `deps.slot!`.
	interface OptionalSlotMap {
		readonly _testOptionalSlot?: { readonly value: string };
	}
	type OptionalKey = keyof OptionalSlotMap;
	type OptionalSlotProviderDeps<R extends OptionalKey = never> = {
		readonly [K in R]: NonNullable<OptionalSlotMap[K]>;
	};

	type Deps = OptionalSlotProviderDeps<"_testOptionalSlot">;
	expectTypeOf<Deps>().branded.toEqualTypeOf<{
		readonly _testOptionalSlot: { readonly value: string };
	}>();
});

test("ProviderDeps<never, never> is an empty object", () => {
	// `.branded`: `{} & {}` is structurally equal to, but not identical with,
	// `Record<never, never>`.
	expectTypeOf<ProviderDeps<never, never>>().branded.toEqualTypeOf<Record<never, never>>();
});

test("Provider<K, Deps> is a function from Deps to ComponentMap[K] | Promise", () => {
	// Mirrors Provider<K, Deps> over the local fixture.
	type LocalCM = LocalComponentMap;
	type LocalProvider<K extends LocalKey, Deps> = (deps: Deps) => LocalCM[K] | Promise<LocalCM[K]>;
	type NoDeps = Record<never, never>;
	type ConfigProvider = LocalProvider<"_testConfig", NoDeps>;
	// The provider's return type is the slot's type or a Promise of it.
	expectTypeOf<ConfigProvider>().toMatchTypeOf<
		(deps: NoDeps) => { readonly host: string } | Promise<{ readonly host: string }>
	>();
});

test("ProviderDeps' third argument adds the module's section, typed as its schema's output", () => {
	const Section = z.object({ retries: z.coerce.number(), label: z.string().optional() });
	expectTypeOf<ProviderDeps<never, never, typeof Section>>().branded.toEqualTypeOf<{
		readonly section: { retries: number; label?: string | undefined };
	}>();
	// A module without a section gets no `section` key at all, not an optional one.
	expectTypeOf<ProviderDeps<never, never>>().not.toHaveProperty("section");
});
