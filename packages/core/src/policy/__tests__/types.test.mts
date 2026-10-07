/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
import { describe, expectTypeOf, it } from "vitest";
import type { GrantPolicyRequest } from "../types.mjs";

describe("GrantPolicyRequest types", () => {
	it("carries the original grant's audience beside its scope, both optional", () => {
		expectTypeOf<GrantPolicyRequest["originalScope"]>().toEqualTypeOf<
			readonly string[] | undefined
		>();
		expectTypeOf<GrantPolicyRequest["originalAudience"]>().toEqualTypeOf<
			readonly string[] | undefined
		>();
	});
});
