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

import { expectTypeOf, it } from "vitest";
import type { ComponentKey, ComponentMap } from "../component-map.mjs";
import type { ComponentLifecycle, ModuleSpec } from "../module-spec.mjs";

// ---------------------------------------------------------------------------
// Declaration-merge a test-only slot into ComponentMap so that we can
// exercise ComponentLifecycle<K> with a concrete value type without
// touching production slot names.
// ---------------------------------------------------------------------------
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly testLifecycleSlot: { readonly value: number };
	}
}

it("ComponentLifecycle<K> declares optional eager: boolean", () => {
	type L = ComponentLifecycle<"testLifecycleSlot">;
	// eager must be present as an optional boolean field
	type EagerType = L["eager"];
	expectTypeOf<EagerType>().toEqualTypeOf<boolean | undefined>();
});

it("ComponentLifecycle<K> declares optional cleanup taking the component value", () => {
	type L = ComponentLifecycle<"testLifecycleSlot">;
	type CleanupType = L["cleanup"];
	// cleanup must be an optional function taking ComponentMap[K] and returning void | Promise<void>
	type ExpectedCleanup =
		| ((value: ComponentMap["testLifecycleSlot"]) => void | Promise<void>)
		| undefined;
	expectTypeOf<CleanupType>().toEqualTypeOf<ExpectedCleanup>();
});

it("ModuleSpec.lifecycle is optional — the simple (deps) => value form remains valid", () => {
	// A ModuleSpec with no lifecycle field is still assignable to ModuleSpec<R, O>
	const spec: ModuleSpec<ComponentKey, ComponentKey> = {
		name: "test-module",
		// lifecycle is deliberately absent
	};
	expectTypeOf(spec).toMatchTypeOf<ModuleSpec<ComponentKey, ComponentKey>>();
	expectTypeOf<ModuleSpec["lifecycle"]>().toEqualTypeOf<
		{ readonly [K in ComponentKey]?: ComponentLifecycle<K> } | undefined
	>();
});

it("ModuleSpec.lifecycle accepts an eager + cleanup map keyed by ComponentKey", () => {
	type Lifecycle = NonNullable<ModuleSpec["lifecycle"]>;
	type SlotEntry = Lifecycle["testLifecycleSlot"];
	// Each entry may be a full ComponentLifecycle or undefined
	expectTypeOf<SlotEntry>().toEqualTypeOf<ComponentLifecycle<"testLifecycleSlot"> | undefined>();
});
