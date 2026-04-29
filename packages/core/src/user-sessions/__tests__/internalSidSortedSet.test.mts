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
import { createMemorySidSortedSet } from "../memory/internalSidSortedSet.mjs";

const FUTURE = () => new Date(Date.now() + 60_000);
const PAST = () => new Date(Date.now() - 1);

describe("createMemorySidSortedSet", () => {
	it("add then list returns inserted member", () => {
		const z = createMemorySidSortedSet();
		z.add("sid-1", "alpha", FUTURE());
		expect(z.list("sid-1")).toEqual(["alpha"]);
	});

	it("add preserves insertion order across multiple adds", () => {
		const z = createMemorySidSortedSet();
		z.add("sid-1", "google", FUTURE());
		z.add("sid-1", "github", FUTURE());
		z.add("sid-1", "gitlab", FUTURE());
		expect(z.list("sid-1")).toEqual(["google", "github", "gitlab"]);
	});

	it("re-add of same member is idempotent — does NOT promote position", () => {
		const z = createMemorySidSortedSet();
		z.add("sid-1", "google", FUTURE());
		z.add("sid-1", "github", FUTURE());
		// Re-adding "google" must NOT move it to the end (insertion-order stable)
		z.add("sid-1", "google", FUTURE());
		expect(z.list("sid-1")).toEqual(["google", "github"]);
	});

	it("add after expiry no-ops (does not recreate zombie)", () => {
		const z = createMemorySidSortedSet();
		z.add("sid-1", "google", PAST());
		expect(z.list("sid-1")).toEqual([]);
	});

	it("list GCs entries past expiry", async () => {
		const z = createMemorySidSortedSet();
		// Widen timing margins to avoid CI flake on loaded runners (per T2 review).
		const soon = new Date(Date.now() + 50);
		z.add("sid-1", "google", soon);
		expect(z.list("sid-1")).toEqual(["google"]);
		await new Promise((r) => setTimeout(r, 100));
		expect(z.list("sid-1")).toEqual([]);
	});

	it("remove(sid, member) removes only the named member", () => {
		const z = createMemorySidSortedSet();
		z.add("sid-1", "google", FUTURE());
		z.add("sid-1", "github", FUTURE());
		z.remove("sid-1", "google");
		expect(z.list("sid-1")).toEqual(["github"]);
	});

	it("remove of absent member is a no-op", () => {
		const z = createMemorySidSortedSet();
		z.add("sid-1", "google", FUTURE());
		expect(() => z.remove("sid-1", "ghost")).not.toThrow();
		expect(z.list("sid-1")).toEqual(["google"]);
	});

	it("removeBySid clears all entries", () => {
		const z = createMemorySidSortedSet();
		z.add("sid-1", "google", FUTURE());
		z.add("sid-1", "github", FUTURE());
		z.removeBySid("sid-1");
		expect(z.list("sid-1")).toEqual([]);
	});

	it("removeBySid is idempotent on absent sid", () => {
		const z = createMemorySidSortedSet();
		expect(() => z.removeBySid("never-existed")).not.toThrow();
	});

	it("list returns a defensive copy", () => {
		const z = createMemorySidSortedSet();
		z.add("sid-1", "google", FUTURE());
		const out = z.list("sid-1");
		(out as string[]).push("evil");
		expect(z.list("sid-1")).toEqual(["google"]);
	});

	it("re-add after remove restarts insertion order at end", () => {
		const z = createMemorySidSortedSet();
		z.add("sid-1", "google", FUTURE());
		z.add("sid-1", "github", FUTURE());
		z.remove("sid-1", "google");
		z.add("sid-1", "google", FUTURE());
		expect(z.list("sid-1")).toEqual(["github", "google"]);
	});
});
