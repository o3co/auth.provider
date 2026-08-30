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

/** The in-memory `DeviceCodeStore` against the shared conformance suite. */

import { describe, expect, it, vi } from "vitest";
import { createMemoryDeviceCodeStore } from "../memory.mjs";
import { runDeviceCodeStoreContract } from "./adapters.contract.mjs";

runDeviceCodeStoreContract("memory", {
	create: () => createMemoryDeviceCodeStore(),
	destroy: (store) => {
		(store as { dispose?: () => void }).dispose?.();
	},
});

describe("memory DeviceCodeStore — sweep", () => {
	it("reclaims expired entries without waiting for a lookup", async () => {
		// `poll` and `findPendingByUserCode` already refuse expired records, so
		// the sweep is about memory, not correctness — which is exactly why it
		// needs its own assertion. Asserting through a lookup would pass with
		// no sweep at all.
		vi.useFakeTimers();
		try {
			const store = createMemoryDeviceCodeStore({ sweepIntervalMs: 50 });
			await store.create({
				deviceCode: "dc-1",
				userCode: "BCDFGHJK",
				clientId: "tv",
				expiresAtMs: Date.now() + 10,
				intervalSeconds: 5,
			});
			expect(store.size()).toBe(1);

			await vi.advanceTimersByTimeAsync(120);
			expect(store.size()).toBe(0);
			store.dispose();
		} finally {
			vi.useRealTimers();
		}
	});
});
