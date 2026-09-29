import { expectTypeOf, test } from "vitest";
import { z } from "zod";
import type { ComponentKey } from "../component-map.mjs";
import { defineModule } from "../define-module.mjs";
import type { ModuleSection, SectionSchema } from "../module-section.mjs";
import type { Module, ModuleSpec } from "../module-spec.mjs";
import type { ProviderDeps } from "../provider.mjs";

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
	// is exported with the expected signature shape: `requires` and
	// `optional` inferred as literals, and the section's schema as a third
	// argument that defaults to "no section".
	type DefineModuleType = typeof defineModule;
	expectTypeOf<DefineModuleType>().toMatchTypeOf<
		<
			const R extends ComponentKey = never,
			const O extends ComponentKey = never,
			S extends SectionSchema = never,
		>(
			spec: ModuleSpec<R, O, S>,
		) => Module
	>();
});

// ---------------------------------------------------------------------------
// The module's own configuration section (#728). `section.schema` types
// `deps.section` in every factory of the module. These call the production
// `defineModule`: `config` is a real slot in this program, declared by
// `../../../boot/types.mts`, which the typecheck program includes.
// ---------------------------------------------------------------------------

const RetrySection = z.object({
	retries: z.number(),
	mode: z.enum(["fast", "slow"]).optional(),
});

test("defineModule types deps.section as the section schema's output", () => {
	const m = defineModule({
		name: "sectioned",
		requires: ["config"],
		section: { schema: RetrySection },
		contributes: {
			grantMiddleware: [
				(deps) => {
					expectTypeOf(deps.section).toEqualTypeOf<z.output<typeof RetrySection>>();
					expectTypeOf(deps.section.retries).toEqualTypeOf<number>();
					expectTypeOf(deps.section.mode).toEqualTypeOf<"fast" | "slow" | undefined>();
					// The section sits beside the module's slots, not in place of them.
					expectTypeOf(deps.config).not.toBeUnknown();
					return null;
				},
			],
		},
	});
	// The erased manifest accepts it: a sectioned module is listed like any other.
	const modules: readonly Module[] = [m];
	expectTypeOf(modules).toEqualTypeOf<readonly Module[]>();
});

test("every factory position of a sectioned manifest receives the section", () => {
	type Spec = ModuleSpec<"config", never, typeof RetrySection>;
	type Expected = z.output<typeof RetrySection>;
	type ProvidesDeps = Parameters<NonNullable<NonNullable<Spec["provides"]>["config"]>>[0];
	type ContributesDeps = Parameters<
		NonNullable<NonNullable<Spec["contributes"]>["grantMiddleware"]>[number]
	>[0];
	type OverridesDeps = Parameters<
		NonNullable<NonNullable<Spec["overrides"]>["mfaFactors"]>[string]
	>[0];
	expectTypeOf<ProvidesDeps["section"]>().toEqualTypeOf<Expected>();
	expectTypeOf<ContributesDeps["section"]>().toEqualTypeOf<Expected>();
	expectTypeOf<OverridesDeps["section"]>().toEqualTypeOf<Expected>();
	// One deps object for every position: ProviderDeps with the schema as its third argument.
	expectTypeOf<ProvidesDeps>().toEqualTypeOf<ProviderDeps<"config", never, typeof RetrySection>>();
});

test("a module that declares no section has no deps.section", () => {
	defineModule({
		name: "unsectioned",
		requires: ["config"],
		contributes: {
			grantMiddleware: [
				(deps) => {
					expectTypeOf(deps).not.toHaveProperty("section");
					// @ts-expect-error — no section is declared, so there is none to read
					void deps.section;
					return null;
				},
			],
		},
	});
});

test("a factory cannot read its section as another type", () => {
	defineModule({
		name: "misread",
		section: { schema: RetrySection },
		contributes: {
			grantMiddleware: [
				(deps) => {
					// @ts-expect-error — `retries` is a number
					const retries: string = deps.section.retries;
					void retries;
					return null;
				},
			],
		},
	});
});

test("section.schema is a Zod schema", () => {
	defineModule({
		name: "not-a-schema",
		// @ts-expect-error — a parse function alone is not a schema
		section: { schema: { parse: (value: unknown) => value } },
	});
});

test("a section declares its reference.conf, a transitional path and the paths it moves from", () => {
	defineModule({
		name: "relocating",
		section: {
			schema: RetrySection,
			reference: new URL("../config/reference.conf", import.meta.url),
			at: "legacy.relocating",
			relocatedFrom: ["older.relocating"],
		},
	});
	expectTypeOf<ModuleSection["schema"]>().toEqualTypeOf<SectionSchema>();
	expectTypeOf<ModuleSection["reference"]>().toEqualTypeOf<URL | undefined>();
	expectTypeOf<ModuleSection["at"]>().toEqualTypeOf<string | undefined>();
	expectTypeOf<ModuleSection["relocatedFrom"]>().toEqualTypeOf<
		readonly string[] | Readonly<Record<string, string | null>> | undefined
	>();
});

test("relocatedFrom is a list of old paths moved whole, or a map from each old path to its path in the section", () => {
	defineModule({
		name: "relocating-map",
		section: {
			schema: RetrySection,
			relocatedFrom: {
				"oauth.retrying": "",
				"oauth.retrying.max-retries": "retries",
				"endpoints.retry.url": "page.url",
				// Removed rather than moved.
				"oauth.retrying.legacy-flag": null,
			},
		},
	});
	defineModule({
		name: "relocating-bad",
		section: {
			schema: RetrySection,
			// @ts-expect-error — a new path is a string of keys
			relocatedFrom: { "oauth.retrying": 1 },
		},
	});
});

test("a call that writes its type arguments and omits the schema's is refused a section", () => {
	defineModule<"config", never>({
		name: "explicit-without-schema",
		requires: ["config"],
		// @ts-expect-error — `S` was not given, so it is `never`: no section may be declared
		section: { schema: RetrySection },
	});
	defineModule<"config", never, typeof RetrySection>({
		name: "explicit-with-schema",
		requires: ["config"],
		section: { schema: RetrySection },
		contributes: {
			grantMiddleware: [
				(deps) => {
					expectTypeOf(deps.section).toEqualTypeOf<z.output<typeof RetrySection>>();
					return null;
				},
			],
		},
	});
});
