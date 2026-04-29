/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
import type { ComponentMap } from "@o3co/auth-provider-core";
import { describe, expectTypeOf, it, test } from "vitest";
// Importing for side-effect: declares redisClient slot via declare module
import "../src/component-map.mjs";
import type { RedisMulti } from "../src/index.mjs";
import type { RedisClient } from "../src/types.mjs";

describe("RedisClient", () => {
	it("exposes the four ops needed by Phase 5 adapters", () => {
		expectTypeOf<RedisClient["set"]>().toEqualTypeOf<
			(
				key: string,
				value: string,
				mode: "PX",
				ttlMs: number,
				condition: "NX",
			) => Promise<"OK" | null>
		>();
		expectTypeOf<RedisClient["del"]>().toEqualTypeOf<(key: string) => Promise<number>>();
		expectTypeOf<RedisClient["pttl"]>().toEqualTypeOf<(key: string) => Promise<number>>();
		expectTypeOf<RedisClient["exists"]>().toEqualTypeOf<(key: string) => Promise<number>>();
	});
});

describe("ComponentMap declaration-merge", () => {
	it("redisClient slot is optional and of RedisClient type", () => {
		expectTypeOf<ComponentMap["redisClient"]>().toEqualTypeOf<RedisClient | undefined>();
	});
});

test("RedisClient additively exposes get / watch / unwatch / multi for A3 CAS", () => {
	type ClientShape = {
		// A1 (existing)
		set(
			key: string,
			value: string,
			mode: "PX",
			ttlMs: number,
			condition: "NX",
		): Promise<"OK" | null>;
		del(key: string): Promise<number>;
		pttl(key: string): Promise<number>;
		exists(key: string): Promise<number>;
		// A3 (new)
		get(key: string): Promise<string | null>;
		watch(...keys: string[]): Promise<"OK">;
		unwatch(): Promise<"OK">;
		multi(): RedisMulti;
	};
	expectTypeOf<RedisClient>().toEqualTypeOf<ClientShape>();
});

test("RedisMulti exposes chainable set + exec returning null on CAS conflict", () => {
	expectTypeOf<RedisMulti>().toEqualTypeOf<{
		set(key: string, value: string, mode: "PX", ttlMs: number): RedisMulti;
		exec(): Promise<unknown[] | null>;
	}>();
});
