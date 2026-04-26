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
import { createInMemorySingleUseTokenStore } from "#/single-use-tokens/adapters/memory.mjs";
import { SingleUseTokenError } from "#/single-use-tokens/types.mjs";

describe("InMemorySingleUseTokenStore — issue", () => {
	it("kind is 'memory'", () => {
		const s = createInMemorySingleUseTokenStore();
		expect(s.kind).toBe("memory");
	});

	it("issue stores a fresh (scope, key) without throwing", async () => {
		const s = createInMemorySingleUseTokenStore();
		await expect(
			s.issue("webauthn:reg", "k1", new Date(Date.now() + 60_000)),
		).resolves.toBeUndefined();
	});

	it("issue rejects expiresAt <= now with reason 'expired-at-issue'", async () => {
		const s = createInMemorySingleUseTokenStore();
		const past = new Date(Date.now() - 1);
		await expect(s.issue("webauthn:reg", "k1", past)).rejects.toMatchObject({
			name: "SingleUseTokenError",
			reason: "expired-at-issue",
		});
	});

	it("issue rejects exactly at expiresAt === now with 'expired-at-issue'", async () => {
		const s = createInMemorySingleUseTokenStore();
		const now = new Date(Date.now());
		await expect(s.issue("webauthn:reg", "k1", now)).rejects.toMatchObject({
			reason: "expired-at-issue",
		});
	});

	it("issue throws 'duplicate' when (scope, key) is already issued and not expired", async () => {
		const s = createInMemorySingleUseTokenStore();
		await s.issue("webauthn:reg", "k1", new Date(Date.now() + 60_000));
		await expect(
			s.issue("webauthn:reg", "k1", new Date(Date.now() + 60_000)),
		).rejects.toMatchObject({ name: "SingleUseTokenError", reason: "duplicate" });
	});

	it("issue accepts re-use of (scope, key) after expiresAt has passed", async () => {
		const s = createInMemorySingleUseTokenStore();
		const justExpired = new Date(Date.now() + 5);
		await s.issue("webauthn:reg", "k1", justExpired);
		await new Promise((r) => setTimeout(r, 10));
		await expect(
			s.issue("webauthn:reg", "k1", new Date(Date.now() + 60_000)),
		).resolves.toBeUndefined();
	});

	it("issue throws SingleUseTokenError instances (not generic Error)", async () => {
		const s = createInMemorySingleUseTokenStore();
		try {
			await s.issue("a", "b", new Date(0));
			expect.fail("should have thrown");
		} catch (err) {
			expect(err).toBeInstanceOf(SingleUseTokenError);
		}
	});
});
