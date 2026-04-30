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

import type { SessionFederationIndex } from "@o3co/auth-provider-core";
import { describe, expect, it } from "vitest";

export type SessionFederationIndexFactory = () => Promise<SessionFederationIndex>;

const FUTURE = () => new Date(Date.now() + 60_000);
const PAST = () => new Date(Date.now() - 1);

export function runSessionFederationIndexContract(factory: SessionFederationIndexFactory): void {
	describe("SessionFederationIndex contract", () => {
		it("addFederation then listFederations returns the name", async () => {
			const idx = await factory();
			await idx.addFederation("sid-1", "google", FUTURE());
			const list = await idx.listFederations("sid-1");
			expect(list).toHaveLength(1);
			expect(list[0]).toBe("google");
		});

		it("addFederation is idempotent on duplicate name", async () => {
			const idx = await factory();
			await idx.addFederation("sid-1", "google", FUTURE());
			await idx.addFederation("sid-1", "google", FUTURE());
			const list = await idx.listFederations("sid-1");
			expect(list).toHaveLength(1);
			expect(list[0]).toBe("google");
		});

		it("listFederations returns names in INSERTION order (load-bearing)", async () => {
			const idx = await factory();
			await idx.addFederation("sid-1", "google", FUTURE());
			await idx.addFederation("sid-1", "github", FUTURE());
			await idx.addFederation("sid-1", "microsoft", FUTURE());
			const list = await idx.listFederations("sid-1");
			expect(list).toEqual(["google", "github", "microsoft"]);
		});

		it("re-add of existing member does NOT promote position (ZADD NX semantics)", async () => {
			const idx = await factory();
			await idx.addFederation("sid-1", "google", FUTURE());
			await idx.addFederation("sid-1", "github", FUTURE());
			await idx.addFederation("sid-1", "google", FUTURE());
			const list = await idx.listFederations("sid-1");
			expect(list).toEqual(["google", "github"]);
		});

		it("removeFederation removes only the named entry", async () => {
			const idx = await factory();
			await idx.addFederation("sid-1", "google", FUTURE());
			await idx.addFederation("sid-1", "github", FUTURE());
			await idx.removeFederation("sid-1", "google");
			const list = await idx.listFederations("sid-1");
			expect(list).toEqual(["github"]);
		});

		it("removeFederation of absent member is no-op", async () => {
			const idx = await factory();
			await idx.addFederation("sid-1", "google", FUTURE());
			await expect(idx.removeFederation("sid-1", "microsoft")).resolves.toBeUndefined();
			const list = await idx.listFederations("sid-1");
			expect(list).toEqual(["google"]);
		});

		it("listFederations returns empty array for unknown sid", async () => {
			const idx = await factory();
			const list = await idx.listFederations("ghost");
			expect(list).toEqual([]);
		});

		it("addFederation after past expiresAt is a no-op", async () => {
			const idx = await factory();
			await idx.addFederation("sid-1", "google", PAST());
			const list = await idx.listFederations("sid-1");
			expect(list).toEqual([]);
		});

		it("listFederations returns empty after expiresAt elapsed", async () => {
			const idx = await factory();
			const soon = new Date(Date.now() + 50);
			await idx.addFederation("sid-1", "google", soon);
			expect(await idx.listFederations("sid-1")).toHaveLength(1);
			await new Promise((r) => setTimeout(r, 100));
			expect(await idx.listFederations("sid-1")).toEqual([]);
		});

		it("removeBySid clears all federations for the sid", async () => {
			const idx = await factory();
			await idx.addFederation("sid-1", "google", FUTURE());
			await idx.addFederation("sid-1", "github", FUTURE());
			await idx.removeBySid("sid-1");
			const list = await idx.listFederations("sid-1");
			expect(list).toEqual([]);
		});

		it("removeBySid is idempotent on absent sid", async () => {
			const idx = await factory();
			await expect(idx.removeBySid("ghost")).resolves.toBeUndefined();
		});

		it("listFederations returns a defensive copy (caller mutation isolated)", async () => {
			const idx = await factory();
			await idx.addFederation("sid-1", "google", FUTURE());
			await idx.addFederation("sid-1", "github", FUTURE());
			const list = await idx.listFederations("sid-1");
			(list as string[]).push("evil");
			expect(await idx.listFederations("sid-1")).toEqual(["google", "github"]);
		});

		it("readonly kind field present", async () => {
			const idx = await factory();
			expect(typeof idx.kind).toBe("string");
			expect(idx.kind.length).toBeGreaterThan(0);
		});
	});
}
