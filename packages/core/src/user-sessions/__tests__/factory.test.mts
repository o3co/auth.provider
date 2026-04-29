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
import {
	createSessionFamilyIndexFactory,
	createSessionFederationIndexFactory,
	createSessionRPRegistryFactory,
	createUserSessionStoreFactory,
} from "../factory.mjs";
import { createInMemorySessionFamilyIndex } from "../memory/sessionFamilyIndex.mjs";
import { createInMemorySessionFederationIndex } from "../memory/sessionFederationIndex.mjs";
import { createInMemorySessionRPRegistry } from "../memory/sessionRPRegistry.mjs";
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

describe("SessionRPRegistryFactory", () => {
	it("registers + resolves the memory builder", async () => {
		const f = createSessionRPRegistryFactory();
		f.register("memory", () => createInMemorySessionRPRegistry());
		const reg = await f.create({ type: "memory" });
		expect(reg.kind).toBe("memory");
	});

	it("kind label is 'SessionRPRegistry' (pins per-factory label, prevents typo regression)", () => {
		const f = createSessionRPRegistryFactory();
		f.register("memory", () => createInMemorySessionRPRegistry());
		expect(() => f.register("memory", () => createInMemorySessionRPRegistry())).toThrow(
			/SessionRPRegistry/,
		);
	});
});

describe("SessionFamilyIndexFactory", () => {
	it("registers + resolves the memory builder", async () => {
		const f = createSessionFamilyIndexFactory();
		f.register("memory", () => createInMemorySessionFamilyIndex());
		const idx = await f.create({ type: "memory" });
		expect(idx.kind).toBe("memory");
	});

	it("kind label is 'SessionFamilyIndex' (pins per-factory label, prevents typo regression)", () => {
		const f = createSessionFamilyIndexFactory();
		f.register("memory", () => createInMemorySessionFamilyIndex());
		expect(() => f.register("memory", () => createInMemorySessionFamilyIndex())).toThrow(
			/SessionFamilyIndex/,
		);
	});
});

describe("SessionFederationIndexFactory", () => {
	it("registers + resolves the memory builder", async () => {
		const f = createSessionFederationIndexFactory();
		f.register("memory", () => createInMemorySessionFederationIndex());
		const idx = await f.create({ type: "memory" });
		expect(idx.kind).toBe("memory");
	});

	it("kind label is 'SessionFederationIndex' (pins per-factory label, prevents typo regression)", () => {
		const f = createSessionFederationIndexFactory();
		f.register("memory", () => createInMemorySessionFederationIndex());
		expect(() => f.register("memory", () => createInMemorySessionFederationIndex())).toThrow(
			/SessionFederationIndex/,
		);
	});
});
