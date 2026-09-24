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

import { describe, expect, it, vi } from "vitest";
import { resolveClientSecret } from "#/federations/client-secret.mjs";

describe("resolveClientSecret", () => {
	it("returns a static string unchanged (Google / GitHub keep working)", async () => {
		await expect(resolveClientSecret("static-secret")).resolves.toBe("static-secret");
	});

	it("calls a sync resolver and returns its value", async () => {
		await expect(resolveClientSecret(() => "sync-secret")).resolves.toBe("sync-secret");
	});

	it("awaits an async resolver", async () => {
		await expect(resolveClientSecret(async () => "async-secret")).resolves.toBe("async-secret");
	});

	it("calls the resolver once per resolution — the caller owns any caching", async () => {
		// The framework deliberately does NOT cache: a rotating secret (Apple's
		// ES256 JWT) has its own expiry, which only the adapter can reason about.
		const resolver = vi.fn(() => "s");
		await resolveClientSecret(resolver);
		await resolveClientSecret(resolver);
		expect(resolver).toHaveBeenCalledTimes(2);
	});

	it("rejects an empty static secret rather than posting an empty client_secret", async () => {
		await expect(resolveClientSecret("")).rejects.toThrow(/client secret/i);
	});

	it("rejects a resolver that returns an empty string", async () => {
		await expect(resolveClientSecret(() => "")).rejects.toThrow(/client secret/i);
	});

	it("rejects a resolver that returns a non-string", async () => {
		await expect(resolveClientSecret((() => 42) as never)).rejects.toThrow(/client secret/i);
	});

	it("rejects a value that is neither a string nor a function", async () => {
		await expect(resolveClientSecret(undefined as never)).rejects.toThrow(/client secret/i);
		await expect(resolveClientSecret(null as never)).rejects.toThrow(/client secret/i);
	});

	it("propagates a resolver failure instead of falling back to a stale secret", async () => {
		await expect(
			resolveClientSecret(() => {
				throw new Error("signing key unavailable");
			}),
		).rejects.toThrow("signing key unavailable");
	});
});
