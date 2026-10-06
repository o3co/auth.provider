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
import { createUserSessionStoreFactory } from "../factory.mjs";
import { createInMemoryUserSessionStore } from "../memory/userSessionStore.mjs";

describe("UserSessionStoreFactory", () => {
	it("registers + resolves the memory builder", async () => {
		const f = createUserSessionStoreFactory();
		f.register("memory", () => createInMemoryUserSessionStore());
		const store = await f.create({ type: "memory" });
		expect(store.kind).toBe("memory");
	});

	it("register throws on duplicate", () => {
		const f = createUserSessionStoreFactory();
		f.register("memory", () => createInMemoryUserSessionStore());
		expect(() => f.register("memory", () => createInMemoryUserSessionStore())).toThrow();
	});

	it("replace overwrites without throwing", async () => {
		const f = createUserSessionStoreFactory();
		f.register("memory", () => createInMemoryUserSessionStore());
		f.replace("memory", () => createInMemoryUserSessionStore());
		const store = await f.create({ type: "memory" });
		expect(store.kind).toBe("memory");
	});
});
