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
import { GrantRegistry, GrantRegistryError } from "#/grants/registry.mjs";
import type { GrantHandler } from "#/grants/types.mjs";

const makeHandler = (_name: string): GrantHandler => ({
	handle: vi.fn().mockResolvedValue({
		result: { status: 200, tokens: {} },
	}),
});

describe("GrantRegistry.register (A6+A7 §2.1: throw on duplicate)", () => {
	it("registers a handler under a fresh name", () => {
		const registry = new GrantRegistry();
		registry.register("foo", makeHandler("a"));
		expect(registry.get("foo")).toBeDefined();
	});

	it("throws GrantRegistryError reason='duplicate' on duplicate name", () => {
		const registry = new GrantRegistry();
		registry.register("foo", makeHandler("a"));
		let caught: unknown;
		try {
			registry.register("foo", makeHandler("b"));
		} catch (e) {
			caught = e;
		}
		expect(caught).toBeInstanceOf(GrantRegistryError);
		if (caught instanceof GrantRegistryError) {
			expect(caught.reason).toBe("duplicate");
			expect(caught.grantType).toBe("foo");
			expect(caught.registered).toEqual(["foo"]);
		}
	});

	it("does NOT silently overwrite — original handler remains after duplicate throw", () => {
		const registry = new GrantRegistry();
		const original = makeHandler("original");
		registry.register("foo", original);
		expect(() => registry.register("foo", makeHandler("replacement"))).toThrow(GrantRegistryError);
		expect(registry.get("foo")).toBe(original);
	});
});

describe("GrantRegistry.replace (A6+A7 §2.2: explicit override)", () => {
	it("overwrites a registered handler (happy path)", () => {
		const registry = new GrantRegistry();
		const original = makeHandler("original");
		const replacement = makeHandler("replacement");
		registry.register("foo", original);
		registry.replace("foo", replacement);
		expect(registry.get("foo")).toBe(replacement);
	});

	it("throws GrantRegistryError reason='unknown' when name is not registered", () => {
		const registry = new GrantRegistry();
		let caught: unknown;
		try {
			registry.replace("absent", makeHandler("x"));
		} catch (e) {
			caught = e;
		}
		expect(caught).toBeInstanceOf(GrantRegistryError);
		if (caught instanceof GrantRegistryError) {
			expect(caught.reason).toBe("unknown");
			expect(caught.grantType).toBe("absent");
			expect(caught.registered).toEqual([]);
		}
	});

	it("throws GrantRegistryError reason='frozen' on a frozen registry", () => {
		const registry = new GrantRegistry();
		registry.register("foo", makeHandler("a"));
		registry.freeze();
		let caught: unknown;
		try {
			registry.replace("foo", makeHandler("b"));
		} catch (e) {
			caught = e;
		}
		expect(caught).toBeInstanceOf(GrantRegistryError);
		if (caught instanceof GrantRegistryError) {
			expect(caught.reason).toBe("frozen");
			expect(caught.grantType).toBe("foo");
		}
	});
});

describe("GrantRegistry.freeze (A6+A7 §2.3: activation boundary)", () => {
	it("blocks register on a frozen registry with reason='frozen'", () => {
		const registry = new GrantRegistry();
		registry.freeze();
		let caught: unknown;
		try {
			registry.register("foo", makeHandler("a"));
		} catch (e) {
			caught = e;
		}
		expect(caught).toBeInstanceOf(GrantRegistryError);
		if (caught instanceof GrantRegistryError) {
			expect(caught.reason).toBe("frozen");
		}
	});

	it("is idempotent (calling freeze twice is a no-op)", () => {
		const registry = new GrantRegistry();
		registry.freeze();
		expect(() => registry.freeze()).not.toThrow();
	});

	it("allows get on a frozen registry", () => {
		const registry = new GrantRegistry();
		registry.register("foo", makeHandler("a"));
		registry.freeze();
		expect(registry.get("foo")).toBeDefined();
	});

	it("frozen precedence: duplicate-after-freeze throws reason='frozen' (NOT 'duplicate')", () => {
		// Per A6+A7 §2.3: "After freeze(): register throws with reason='frozen'".
		// This is unconditional — when both freeze and duplicate conditions
		// hold, "frozen" wins. The frozen check runs before the duplicate
		// check in the impl to honour this precedence.
		const registry = new GrantRegistry();
		registry.register("foo", makeHandler("a"));
		registry.freeze();
		let caught: unknown;
		try {
			registry.register("foo", makeHandler("b"));
		} catch (e) {
			caught = e;
		}
		expect(caught).toBeInstanceOf(GrantRegistryError);
		if (caught instanceof GrantRegistryError) {
			expect(caught.reason).toBe("frozen");
			expect(caught.grantType).toBe("foo");
		}
	});
});

describe("GrantRegistry.entries (what boot's grants collector lists)", () => {
	it("lists every registered handler, in registration order", () => {
		const registry = new GrantRegistry();
		const foo = makeHandler("foo");
		const bar = makeHandler("bar");
		registry.register("foo", foo);
		registry.register("bar", bar);
		expect([...registry.entries()]).toEqual([
			["foo", foo],
			["bar", bar],
		]);
	});

	it("lists a replaced handler in the place of the one it replaced", () => {
		const registry = new GrantRegistry();
		const bar = makeHandler("bar");
		const replacement = makeHandler("replacement");
		registry.register("foo", makeHandler("foo"));
		registry.register("bar", bar);
		registry.replace("foo", replacement);
		expect([...registry.entries()]).toEqual([
			["foo", replacement],
			["bar", bar],
		]);
	});

	it("is left as it was by a refused register or replace", () => {
		const registry = new GrantRegistry();
		const foo = makeHandler("foo");
		registry.register("foo", foo);
		expect(() => registry.register("foo", makeHandler("duplicate"))).toThrow(GrantRegistryError);
		expect(() => registry.replace("absent", makeHandler("absent"))).toThrow(GrantRegistryError);
		registry.freeze();
		expect(() => registry.register("late", makeHandler("late"))).toThrow(GrantRegistryError);
		expect([...registry.entries()]).toEqual([["foo", foo]]);
	});
});

describe("GrantRegistryError (A6+A7 §2.4: error class shape)", () => {
	it("carries reason, grantType, and registered snapshot", () => {
		const err = new GrantRegistryError({
			reason: "duplicate",
			grantType: "foo",
			registered: ["foo", "bar"],
		});
		expect(err.reason).toBe("duplicate");
		expect(err.grantType).toBe("foo");
		expect(err.registered).toEqual(["foo", "bar"]);
		expect(err.name).toBe("GrantRegistryError");
		expect(err.message).toContain("duplicate");
		expect(err.message).toContain("foo");
	});

	it("formats unknown-reason message with empty registered list", () => {
		const err = new GrantRegistryError({
			reason: "unknown",
			grantType: "absent",
			registered: [],
		});
		expect(err.message).toContain("unknown");
		expect(err.message).toContain("absent");
	});

	it("formats frozen-reason message", () => {
		const err = new GrantRegistryError({
			reason: "frozen",
			grantType: "foo",
			registered: ["foo"],
		});
		expect(err.message).toContain("frozen");
	});
});
