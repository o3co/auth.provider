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

/**
 * `memoryDeviceCodeStoreModule` — the store's `dispose` has to reach
 * `AppHandle.dispose()`, or a sweep timer an operator turns on holds the
 * process open and a test that boots the app leaks it.
 */

import { describe, expect, it, vi } from "vitest";
import { memoryDeviceCodeStoreModule } from "#/device-authorization/module.mjs";

describe("memoryDeviceCodeStoreModule", () => {
	it("declares the lifecycle registrar as an optional dependency", () => {
		expect(memoryDeviceCodeStoreModule.optional).toContain("lifecycleRegistrar");
	});

	it("registers the store's disposal with the lifecycle registrar", async () => {
		const register = vi.fn<(cleanup: () => Promise<void>) => void>();
		const provide = memoryDeviceCodeStoreModule.provides?.deviceCodeStore as (
			deps: unknown,
		) => unknown;
		const store = provide({ lifecycleRegistrar: { register } });

		expect(store).toBeDefined();
		expect(register).toHaveBeenCalledTimes(1);
		const cleanup = register.mock.calls[0]?.[0];
		expect(typeof cleanup).toBe("function");
		await expect(cleanup?.()).resolves.toBeUndefined();
	});

	it("still provides a store when no registrar is wired", () => {
		// A hand-built composition without the boot planner's registrar gets a
		// working store rather than a crash at construction.
		const provide = memoryDeviceCodeStoreModule.provides?.deviceCodeStore as (deps: unknown) => {
			kind: string;
		};
		expect(provide({}).kind).toBe("memory");
	});
});
