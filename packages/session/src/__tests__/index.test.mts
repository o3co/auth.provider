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

import { describe, expect, it } from "vitest";

describe("package public surface (@o3co/auth-provider-session)", () => {
	it("exports supportsLogout as a runtime helper", async () => {
		const mod = await import("#/index.mjs");
		expect(typeof (mod as { supportsLogout?: unknown }).supportsLogout).toBe("function");
	});

	it("does not export the removed FederationProvider / VerifyUserContext names as runtime values", async () => {
		const mod = await import("#/index.mjs");
		// These are type-only exports and would not appear as runtime values anyway;
		// this assertion documents the intended invariant.
		expect((mod as Record<string, unknown>).FederationProvider).toBeUndefined();
		expect((mod as Record<string, unknown>).VerifyUserContext).toBeUndefined();
	});
});
