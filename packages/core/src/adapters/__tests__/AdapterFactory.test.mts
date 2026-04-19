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
import {
	AdapterFactoryError,
	type BuilderContext,
	createAdapterFactory,
} from "#/adapters/AdapterFactory.mjs";

interface MockAdapter {
	name: string;
}

describe("AdapterFactoryError", () => {
	it("formats the message with kind, requested type, and registered types", () => {
		const err = new AdapterFactoryError({
			reason: "unknown",
			kind: "UserRepository",
			type: "postgres",
			registered: ["yaml", "http"],
		});

		expect(err).toBeInstanceOf(Error);
		expect(err.name).toBe("AdapterFactoryError");
		expect(err.message).toBe(
			'AdapterFactoryError [UserRepository]: unknown type "postgres". Registered types: yaml, http',
		);
		expect(err.reason).toBe("unknown");
		expect(err.kind).toBe("UserRepository");
		expect(err.type).toBe("postgres");
		expect(err.registered).toEqual(["yaml", "http"]);
	});

	it("handles empty registered list", () => {
		const err = new AdapterFactoryError({
			reason: "unknown",
			kind: "SessionStore",
			type: "memcached",
			registered: [],
		});

		expect(err.message).toBe(
			'AdapterFactoryError [SessionStore]: unknown type "memcached". No types registered',
		);
	});

	it("formats duplicate-type message", () => {
		const err = new AdapterFactoryError({
			reason: "duplicate",
			kind: "UserRepository",
			type: "yaml",
			registered: ["yaml"],
		});

		expect(err.reason).toBe("duplicate");
		expect(err.message).toBe(
			'AdapterFactoryError [UserRepository]: type "yaml" is already registered. Registered types: yaml',
		);
	});
});

describe("createAdapterFactory", () => {
	it("creates an instance from a registered sync builder", async () => {
		const factory = createAdapterFactory<MockAdapter>("Mock");
		factory.register("static", (config) => ({ name: config.label as string }));

		const adapter = await factory.create({ type: "static", label: "test" });

		expect(adapter.name).toBe("test");
	});

	it("creates an instance from a registered async builder", async () => {
		const factory = createAdapterFactory<MockAdapter>("Mock");
		factory.register("async", async (config) => ({ name: `async-${config.id}` }));

		const adapter = await factory.create({ type: "async", id: "42" });

		expect(adapter.name).toBe("async-42");
	});

	it("throws AdapterFactoryError for an unknown type with registered types listed", async () => {
		const factory = createAdapterFactory<MockAdapter>("Mock");
		factory.register("a", () => ({ name: "a" }));
		factory.register("b", () => ({ name: "b" }));

		await expect(factory.create({ type: "unknown" })).rejects.toBeInstanceOf(AdapterFactoryError);
		await expect(factory.create({ type: "unknown" })).rejects.toThrow(
			/AdapterFactoryError \[Mock\]: unknown type "unknown"\. Registered types: a, b/,
		);

		try {
			await factory.create({ type: "unknown" });
		} catch (err) {
			expect(err).toBeInstanceOf(AdapterFactoryError);
			const e = err as AdapterFactoryError;
			expect(e.reason).toBe("unknown");
			expect(e.kind).toBe("Mock");
			expect(e.type).toBe("unknown");
			expect(e.registered).toEqual(expect.arrayContaining(["a", "b"]));
		}
	});

	it("throws AdapterFactoryError for an unknown type when nothing is registered", async () => {
		const factory = createAdapterFactory<MockAdapter>("Mock");

		await expect(factory.create({ type: "x" })).rejects.toThrow(
			/AdapterFactoryError \[Mock\]: unknown type "x"\. No types registered/,
		);
	});

	it("throws AdapterFactoryError when the same type is registered twice", () => {
		const factory = createAdapterFactory<MockAdapter>("Mock");
		factory.register("x", () => ({ name: "first" }));

		expect(() => factory.register("x", () => ({ name: "second" }))).toThrowError(
			AdapterFactoryError,
		);
		try {
			factory.register("x", () => ({ name: "second" }));
		} catch (err) {
			expect(err).toBeInstanceOf(AdapterFactoryError);
			const e = err as AdapterFactoryError;
			expect(e.reason).toBe("duplicate");
			expect(e.kind).toBe("Mock");
			expect(e.type).toBe("x");
			expect(e.registered).toEqual(["x"]);
		}
	});

	it("registeredTypes() returns a snapshot array of registered type names", () => {
		const factory = createAdapterFactory<MockAdapter>("Mock");
		factory.register("a", () => ({ name: "a" }));
		factory.register("b", () => ({ name: "b" }));

		expect(factory.registeredTypes().sort()).toEqual(["a", "b"]);
	});

	it("passes full config (including type) to the builder", async () => {
		const builder = vi.fn(() => ({ name: "ok" }));
		const factory = createAdapterFactory<MockAdapter>("Mock");
		factory.register("test", builder);

		await factory.create({ type: "test", extra: "value" });

		expect(builder).toHaveBeenCalledWith({ type: "test", extra: "value" }, expect.any(Object));
	});

	it("passes factory-level context to every builder invocation", async () => {
		// extend BuilderContext inline for the test (simulates future field addition)
		interface TestCtx extends BuilderContext {
			tag?: string;
		}
		const ctx: TestCtx = { tag: "hello" };
		const builder = vi.fn((_config, receivedCtx: TestCtx) => ({
			name: receivedCtx.tag ?? "",
		}));

		const factory = createAdapterFactory<MockAdapter>("Mock", ctx);
		factory.register("test", builder);

		const adapter = await factory.create({ type: "test" });

		expect(adapter.name).toBe("hello");
		expect(builder).toHaveBeenCalledWith(
			{ type: "test" },
			expect.objectContaining({ tag: "hello" }),
		);
	});

	it("passes an empty BuilderContext when ctx is not provided", async () => {
		const builder = vi.fn(() => ({ name: "ok" }));
		const factory = createAdapterFactory<MockAdapter>("Mock");
		factory.register("test", builder);

		await factory.create({ type: "test" });

		expect(builder).toHaveBeenCalledWith({ type: "test" }, {});
	});

	it("normalises sync builder return values to Promise<T>", async () => {
		const factory = createAdapterFactory<MockAdapter>("Mock");
		factory.register("sync", () => ({ name: "sync-value" }));

		const result = factory.create({ type: "sync" });

		expect(result).toBeInstanceOf(Promise);
		await expect(result).resolves.toEqual({ name: "sync-value" });
	});

	it("freezes the BuilderContext so builders cannot mutate it", async () => {
		interface TestCtx extends BuilderContext {
			tag?: string;
		}
		const originalCtx: TestCtx = { tag: "hello" };
		const factory = createAdapterFactory<MockAdapter>("Mock", originalCtx);

		let receivedCtx: TestCtx | undefined;
		factory.register("test", (_config, ctx) => {
			receivedCtx = ctx as TestCtx;
			return { name: "ok" };
		});

		await factory.create({ type: "test" });

		expect(Object.isFrozen(receivedCtx)).toBe(true);
		expect(() => {
			(receivedCtx as { tag?: string }).tag = "mutated";
		}).toThrow(TypeError);
	});

	it("isolates factory's frozen ctx from caller's mutations of the original ctx", async () => {
		interface TestCtx extends BuilderContext {
			tag?: string;
		}
		const originalCtx: TestCtx = { tag: "hello" };
		const factory = createAdapterFactory<MockAdapter>("Mock", originalCtx);

		// Mutate original after factory creation
		originalCtx.tag = "mutated-after-creation";

		let receivedTag: string | undefined;
		factory.register("test", (_config, ctx) => {
			receivedTag = (ctx as TestCtx).tag;
			return { name: "ok" };
		});

		await factory.create({ type: "test" });

		// Builder should see the pre-freeze value ("hello"), not the mutation
		expect(receivedTag).toBe("hello");
	});
});
