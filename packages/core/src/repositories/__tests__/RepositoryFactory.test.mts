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
import { RepositoryFactory } from "#/repositories/RepositoryFactory.mjs";

interface MockRepo {
	name: string;
}

describe("RepositoryFactory", () => {
	it("creates instance from registered sync builder", async () => {
		const factory = new RepositoryFactory<MockRepo>("mock");
		factory.register("static", (config) => ({ name: config.label as string }));

		const repo = await factory.create({ type: "static", label: "test" });

		expect(repo.name).toBe("test");
	});

	it("creates instance from registered async builder", async () => {
		const factory = new RepositoryFactory<MockRepo>("mock");
		factory.register("async", async (config) => {
			return { name: `async-${config.id}` };
		});

		const repo = await factory.create({ type: "async", id: "42" });

		expect(repo.name).toBe("async-42");
	});

	it("throws for unregistered type with registered types listed", async () => {
		const factory = new RepositoryFactory<MockRepo>("mock");
		factory.register("a", () => ({ name: "a" }));
		factory.register("b", () => ({ name: "b" }));

		await expect(factory.create({ type: "unknown" })).rejects.toThrow(
			/Unknown mock repository type: "unknown"\. Registered types: a, b/,
		);
	});

	it("throws for unregistered type with no types registered", async () => {
		const factory = new RepositoryFactory<MockRepo>("mock");

		await expect(factory.create({ type: "x" })).rejects.toThrow(
			/Unknown mock repository type: "x"\. No types registered/,
		);
	});

	it("passes full config including type to builder", async () => {
		const builder = vi.fn(() => ({ name: "test" }));
		const factory = new RepositoryFactory<MockRepo>("mock");
		factory.register("test", builder);

		await factory.create({ type: "test", extra: "value" });

		expect(builder).toHaveBeenCalledWith({ type: "test", extra: "value" });
	});

	it("allows overwriting a registered type", async () => {
		const factory = new RepositoryFactory<MockRepo>("mock");
		factory.register("x", () => ({ name: "first" }));
		factory.register("x", () => ({ name: "second" }));

		const repo = await factory.create({ type: "x" });

		expect(repo.name).toBe("second");
	});
});
