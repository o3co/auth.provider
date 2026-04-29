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
import { createMemorySidHash } from "../memory/internalSidHash.mjs";

interface Item {
	readonly id: string;
	readonly payload: string;
}
const idOf = (it: Item) => it.id;
const FUTURE = () => new Date(Date.now() + 60_000);
const PAST = () => new Date(Date.now() - 1);

describe("createMemorySidHash", () => {
	it("setField then listValues returns inserted value", () => {
		const h = createMemorySidHash<Item>(idOf);
		h.setField("sid-1", { id: "a", payload: "v1" }, FUTURE());
		expect(h.listValues("sid-1")).toEqual([{ id: "a", payload: "v1" }]);
	});

	it("setField with same id replaces (upsert by id)", () => {
		const h = createMemorySidHash<Item>(idOf);
		h.setField("sid-1", { id: "a", payload: "v1" }, FUTURE());
		h.setField("sid-1", { id: "a", payload: "v2" }, FUTURE());
		expect(h.listValues("sid-1")).toEqual([{ id: "a", payload: "v2" }]);
	});

	it("setField with distinct ids accumulates", () => {
		const h = createMemorySidHash<Item>(idOf);
		h.setField("sid-1", { id: "a", payload: "v1" }, FUTURE());
		h.setField("sid-1", { id: "b", payload: "v2" }, FUTURE());
		expect(h.listValues("sid-1").sort((x, y) => x.id.localeCompare(y.id))).toEqual([
			{ id: "a", payload: "v1" },
			{ id: "b", payload: "v2" },
		]);
	});

	it("setField after expiry no-ops (does not recreate zombie entry)", () => {
		const h = createMemorySidHash<Item>(idOf);
		h.setField("sid-1", { id: "a", payload: "v1" }, PAST());
		expect(h.listValues("sid-1")).toEqual([]);
	});

	it("listValues GCs entries past expiry", async () => {
		const h = createMemorySidHash<Item>(idOf);
		const expiresSoon = new Date(Date.now() + 20);
		h.setField("sid-1", { id: "a", payload: "v1" }, expiresSoon);
		expect(h.listValues("sid-1")).toEqual([{ id: "a", payload: "v1" }]);
		await new Promise((resolve) => setTimeout(resolve, 30));
		expect(h.listValues("sid-1")).toEqual([]);
	});

	it("removeBySid clears all entries for that sid", () => {
		const h = createMemorySidHash<Item>(idOf);
		h.setField("sid-1", { id: "a", payload: "v1" }, FUTURE());
		h.setField("sid-1", { id: "b", payload: "v2" }, FUTURE());
		h.removeBySid("sid-1");
		expect(h.listValues("sid-1")).toEqual([]);
	});

	it("removeBySid is idempotent on absent sid", () => {
		const h = createMemorySidHash<Item>(idOf);
		expect(() => h.removeBySid("never-existed")).not.toThrow();
	});

	it("returned listValues is a copy — caller mutation does not affect store", () => {
		const h = createMemorySidHash<Item>(idOf);
		h.setField("sid-1", { id: "a", payload: "v1" }, FUTURE());
		const out = h.listValues("sid-1");
		(out as Item[]).push({ id: "x", payload: "evil" });
		expect(h.listValues("sid-1")).toEqual([{ id: "a", payload: "v1" }]);
	});
});
