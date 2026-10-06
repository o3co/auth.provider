/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import type { z } from "zod";
import type { AbsencePolicy } from "./absence-policy.mjs";
import type { ComponentKey, ComponentMap } from "./component-map.mjs";
import type { ContributesMap } from "./contributes-map.mjs";
import type { ModuleSection, SectionSchema } from "./module-section.mjs";
import type { Provider, ProviderDeps } from "./provider.mjs";

/**
 * Lifecycle hooks a module declares for one of its provided slots; `K` types
 * `cleanup`'s value as `ComponentMap[K]`.
 */
export interface ComponentLifecycle<K extends ComponentKey> {
	/** When `true`, instantiate at `createApp` even if nothing depends on it. Default lazy. */
	readonly eager?: boolean;
	/**
	 * Called on `app.dispose()`, in reverse-topological order, with the resolved
	 * value. Errors aggregate into the `AggregateError` that `dispose()` rejects with.
	 */
	readonly cleanup?: (value: ComponentMap[K]) => void | Promise<void>;
}

/**
 * A module's statement that the state it provides lives in this process's
 * memory and **must** be shared for more than one replica to run correctly.
 *
 * The replica-safety guard reads it off every installed manifest:
 * `core.deployment.mode = "multi"` refuses boot naming the module, unset warns,
 * `"single"` is silent. The module declares it because the module is where the
 * fact is known, so a composition root's own in-memory modules are covered too.
 *
 * `reason` is quoted into the refusal and the warning. Name what diverges and
 * what that costs ("back-channel logout reaches only the replica that received
 * it"): "use redis" tells an operator what to type, not what breaks.
 */
export interface ReplicaSafetyDeclaration {
	/**
	 * Always `true`, so the declaration reads as one at the call site
	 * (`replicaSafety: { unsafe: true, reason }`) and a future exemption shape
	 * has somewhere to go.
	 */
	readonly unsafe: true;
	/** What forks per replica, and the consequence for a user or operator. */
	readonly reason: string;
}

/**
 * What a declaration made from the section is handed: the schema's output,
 * `never` without a section, and `never` for the widest schema
 * ({@link SectionSchema}, the erased `Module`), so every manifest's function
 * is assignable to the erased one, as `SectionDeps` does for the deps.
 */
type SectionValue<S extends SectionSchema> = [SectionSchema] extends [S] ? never : z.output<S>;

/**
 * Parameterised manifest type. `defineModule` infers `R` / `O` from the literal
 * `requires` / `optional` arrays, so providers and factories get typed deps.
 * `S`, the section's schema, types `deps.section`: inferred from
 * `section.schema`, `never` without a section, and when written out defaulting
 * to the erased `SectionSchema`, so `ModuleSpec<ComponentKey, ComponentKey>` is
 * `Module`.
 */
export interface ModuleSpec<
	R extends ComponentKey = never,
	O extends ComponentKey = never,
	S extends SectionSchema = SectionSchema,
	P extends ComponentKey = ComponentKey,
> {
	/** Module identity — unique across all modules in a single createApp call. */
	readonly name: string;

	/**
	 * The module's own configuration section, at the top-level key named
	 * exactly as the module: its schema, and the `reference.conf` holding its
	 * defaults. Parsed at stage 1 and passed to
	 * every factory in `provides`, `contributes` and `overrides` as
	 * `deps.section`, typed as the schema's output. See {@link ModuleSection}.
	 */
	readonly section?: ModuleSection<S>;

	/**
	 * Component keys this module reads from DI. Required keys appear as
	 * `readonly K: ComponentMap[K]` on the typed deps object passed to
	 * every provider in `provides` and every factory in `contributes`.
	 */
	readonly requires?: readonly R[];

	/**
	 * Component keys this module reads opportunistically. Optional keys
	 * appear as `readonly K?: ComponentMap[K]` on the typed deps.
	 */
	readonly optional?: readonly O[];

	/**
	 * Declared-absence policies for optional keys: optional to *wire*, not to
	 * *decide*. When nothing fills the slot, the config must carry the policy's
	 * declared-absent value or boot refuses (`component-absence-undeclared`).
	 *
	 * Keys are typed against `O`, but `const O` inference can *widen* `O` from a
	 * policy key instead of checking it, so stage 1 also refuses a policy key
	 * missing from this module's `requires` or `optional`. See
	 * `manifest/absence-policy.mts`.
	 */
	readonly absencePolicies?: { readonly [K in O]?: AbsencePolicy };

	/**
	 * Declares in-process state that must be shared across replicas; read by the
	 * replica-safety guard at stage 1 (see {@link ReplicaSafetyDeclaration}).
	 * Omit it when the module's state lives in a shared store, or it holds none.
	 *
	 * Where the section decides what the module holds (a storage type), declare
	 * it as a function of the parsed section, answering the declaration or
	 * `undefined`. Stage 1 calls it once, after the parse and only for a module
	 * switched on; a module without a section is handed `undefined`. A throw, or
	 * an answer that is neither `undefined` nor `{ unsafe: true, reason }` with
	 * a non-empty `reason`, refuses boot (`config-validation-failed`, naming the
	 * module, and its section's path when it has one), before any wiring check.
	 */
	readonly replicaSafety?:
		| ReplicaSafetyDeclaration
		| ((section: SectionValue<S>) => ReplicaSafetyDeclaration | undefined);

	/**
	 * Component values this module materialises into the DI graph, each
	 * `(deps) => ComponentMap[K] | Promise<ComponentMap[K]>`. The intersection's
	 * second member only carries the provided keys to `P` for `authoritative`.
	 */
	readonly provides?: {
		readonly [K in ComponentKey]?: Provider<K, ProviderDeps<R, O, S>>;
	} & { readonly [K in P]?: unknown };

	/**
	 * Keys of `provides` no composition may substitute while this module is
	 * loaded: settings other modules read as this module's own, derived from its
	 * section. The module's own code reads that section, so an
	 * `overrideComponents` entry would be a second source its readers follow
	 * while the module does not. Stage 1 refuses such an override
	 * (`authoritative-component-overridden`) and a key the module does not
	 * provide (`authoritative-without-provides`). A composition without the
	 * module fills the slot itself, override included.
	 *
	 * Only an inferred `P` holds the list to the provided keys; a `P` written as
	 * the fourth type argument is taken as given, and stage 1's
	 * `authoritative-closure` refuses a key the module does not provide.
	 */
	readonly authoritative?: readonly NoInfer<P>[];

	/** Protocol-level features this module adds (grants, routes, federations, etc.). */
	readonly contributes?: ContributesMap<ProviderDeps<R, O, S>>;

	/**
	 * Protocol-level features this module REPLACES on an already-registered
	 * key. Mirrors `contributes`. A missing target key throws at boot.
	 */
	readonly overrides?: ContributesMap<ProviderDeps<R, O, S>>;

	/**
	 * Per-component lifecycle hooks. Each key MUST also appear in `provides`,
	 * or boot throws `lifecycle-without-provides`.
	 */
	readonly lifecycle?: {
		readonly [K in ComponentKey]?: ComponentLifecycle<K>;
	};
}

/**
 * Erased ModuleSpec: what the boot planner accepts in `Module[]`. Authoring
 * uses `defineModule(...)`, which keeps `R` / `O` by inference.
 *
 * `R` and `O` are widened to `ComponentKey` (not the default `never`) on
 * purpose: any `ModuleSpec<R', O'>` is then assignable, since `requires` /
 * `optional` are covariant in them and `Provider`'s `deps` parameter is
 * contravariant. With `never`, every `defineModule({ requires: [...] })` would
 * be rejected (`readonly "key"[]` does not extend `readonly never[]`).
 *
 * `S = SectionSchema` (the default) erases the section the same way:
 * `section.schema` is covariant in it, and the widest schema reads as
 * `section: never` in the deps (`SectionDeps`), which every factory accepts.
 */
export type Module = ModuleSpec<ComponentKey, ComponentKey>;
