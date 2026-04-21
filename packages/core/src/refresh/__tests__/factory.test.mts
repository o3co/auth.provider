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
import { createRefreshTokenStoreFactory } from "#/refresh/factory.mjs";
import { createInMemoryRefreshTokenStore } from "./fixtures.mjs";

describe("createRefreshTokenStoreFactory", () => {
	it("creates factory and resolves registered stores", async () => {
		const factory = createRefreshTokenStoreFactory();
		factory.register("memory", () => createInMemoryRefreshTokenStore());
		const store = await factory.create({ type: "memory" });
		expect(store.kind).toBe("memory");
	});
});

describe("RefreshTokenStoreBase contract (via fixture)", () => {
	it("rotate returns 'rotated' for an initial grant (previousJti=null)", async () => {
		const store = createInMemoryRefreshTokenStore();
		const result = await store.rotate(null, "new-1", "fam-1", new Date(Date.now() + 60_000));
		expect(result.outcome).toBe("rotated");
	});

	it("rotate returns 'rotated' for a valid chain step", async () => {
		const store = createInMemoryRefreshTokenStore();
		await store.rotate(null, "n1", "f1", new Date(Date.now() + 60_000));
		const r = await store.rotate("n1", "n2", "f1", new Date(Date.now() + 60_000));
		expect(r.outcome).toBe("rotated");
	});

	it("rotate returns 'replayed' on consumed previousJti and revokes the family", async () => {
		const store = createInMemoryRefreshTokenStore();
		await store.rotate(null, "n1", "f1", new Date(Date.now() + 60_000));
		await store.rotate("n1", "n2", "f1", new Date(Date.now() + 60_000));
		const r = await store.rotate("n1", "n3", "f1", new Date(Date.now() + 60_000));
		expect(r.outcome).toBe("replayed");
		if (r.outcome === "replayed") expect(r.familyId).toBe("f1");
		expect(await store.isFamilyRevoked("f1")).toBe(true);
	});

	it("rotate returns 'unknown' when previousJti is absent", async () => {
		const store = createInMemoryRefreshTokenStore();
		const r = await store.rotate("never-issued", "n1", "f1", new Date(Date.now() + 60_000));
		expect(r.outcome).toBe("unknown");
	});

	it("rotate returns 'revoked' for revoked families", async () => {
		const store = createInMemoryRefreshTokenStore();
		await store.revokeFamily("f1");
		const r = await store.rotate(null, "n1", "f1", new Date(Date.now() + 60_000));
		expect(r.outcome).toBe("revoked");
	});

	it("concurrent rotate with same previousJti yields exactly one 'rotated' and one 'replayed'", async () => {
		const store = createInMemoryRefreshTokenStore();
		await store.rotate(null, "base", "f1", new Date(Date.now() + 60_000));
		const [a, b] = await Promise.all([
			store.rotate("base", "child-a", "f1", new Date(Date.now() + 60_000)),
			store.rotate("base", "child-b", "f1", new Date(Date.now() + 60_000)),
		]);
		const outcomes = [a.outcome, b.outcome].sort();
		expect(outcomes).toEqual(["replayed", "rotated"]);
	});
});
