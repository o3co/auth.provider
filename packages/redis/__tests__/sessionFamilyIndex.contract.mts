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

import type { SessionFamilyIndex } from "@o3co/auth-provider-core";
import { describe, expect, it } from "vitest";

export type SessionFamilyIndexFactory = () => Promise<SessionFamilyIndex>;

const FUTURE = () => new Date(Date.now() + 60_000);
const PAST = () => new Date(Date.now() - 1);

export function runSessionFamilyIndexContract(factory: SessionFamilyIndexFactory): void {
	describe("SessionFamilyIndex contract", () => {
		it("addFamilyId then listFamilyIds returns the id", async () => {
			const idx = await factory();
			await idx.addFamilyId("sid-1", "fam-A", FUTURE());
			const list = await idx.listFamilyIds("sid-1");
			expect(list).toHaveLength(1);
			expect(list[0]).toBe("fam-A");
		});

		it("addFamilyId is idempotent on duplicate familyId", async () => {
			const idx = await factory();
			await idx.addFamilyId("sid-1", "fam-A", FUTURE());
			await idx.addFamilyId("sid-1", "fam-A", FUTURE());
			const list = await idx.listFamilyIds("sid-1");
			expect(list).toHaveLength(1);
			expect(list[0]).toBe("fam-A");
		});

		it("distinct ids accumulate in insertion order", async () => {
			const idx = await factory();
			await idx.addFamilyId("sid-1", "fam-A", FUTURE());
			await idx.addFamilyId("sid-1", "fam-B", FUTURE());
			await idx.addFamilyId("sid-1", "fam-C", FUTURE());
			const list = await idx.listFamilyIds("sid-1");
			expect(list).toEqual(["fam-A", "fam-B", "fam-C"]);
		});

		it("listFamilyIds returns empty array for unknown sid", async () => {
			const idx = await factory();
			const list = await idx.listFamilyIds("ghost");
			expect(list).toEqual([]);
		});

		it("addFamilyId after past expiresAt is a no-op", async () => {
			const idx = await factory();
			await idx.addFamilyId("sid-1", "fam-A", PAST());
			const list = await idx.listFamilyIds("sid-1");
			expect(list).toEqual([]);
		});

		it("listFamilyIds returns empty after expiresAt elapsed", async () => {
			const idx = await factory();
			const soon = new Date(Date.now() + 50);
			await idx.addFamilyId("sid-1", "fam-A", soon);
			expect(await idx.listFamilyIds("sid-1")).toHaveLength(1);
			await new Promise((r) => setTimeout(r, 100));
			expect(await idx.listFamilyIds("sid-1")).toEqual([]);
		});

		it("removeBySid clears all family ids for the sid", async () => {
			const idx = await factory();
			await idx.addFamilyId("sid-1", "fam-A", FUTURE());
			await idx.addFamilyId("sid-1", "fam-B", FUTURE());
			await idx.removeBySid("sid-1");
			const list = await idx.listFamilyIds("sid-1");
			expect(list).toEqual([]);
		});

		it("removeBySid is idempotent on absent sid", async () => {
			const idx = await factory();
			await expect(idx.removeBySid("ghost")).resolves.toBeUndefined();
		});

		it("listFamilyIds returns a defensive copy (caller mutation isolated)", async () => {
			const idx = await factory();
			await idx.addFamilyId("sid-1", "fam-A", FUTURE());
			await idx.addFamilyId("sid-1", "fam-B", FUTURE());
			const list = await idx.listFamilyIds("sid-1");
			(list as string[]).push("evil");
			expect(await idx.listFamilyIds("sid-1")).toEqual(["fam-A", "fam-B"]);
		});

		it("readonly kind field present", async () => {
			const idx = await factory();
			expect(typeof idx.kind).toBe("string");
			expect(idx.kind.length).toBeGreaterThan(0);
		});
	});
}
