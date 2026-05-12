/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
import { describe, expectTypeOf, it } from "vitest";
import type { AdapterFactory } from "../../adapters/AdapterFactory.mjs";
import type { AccessTokenDenylistFactory } from "../factory.mjs";
import type { AccessTokenDenylist } from "../types.mjs";

describe("AccessTokenDenylist types", () => {
	it("declares the contract operations", () => {
		expectTypeOf<AccessTokenDenylist["kind"]>().toEqualTypeOf<string>();
		expectTypeOf<AccessTokenDenylist["add"]>().toEqualTypeOf<
			(jti: string, expiresAtMs: number) => Promise<void>
		>();
		expectTypeOf<AccessTokenDenylist["has"]>().toEqualTypeOf<(jti: string) => Promise<boolean>>();
	});

	it("factory type is AdapterFactory<AccessTokenDenylist>", () => {
		expectTypeOf<AccessTokenDenylistFactory>().toEqualTypeOf<AdapterFactory<AccessTokenDenylist>>();
	});
});
