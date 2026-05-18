/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

import { describe, expect, it } from "vitest";
import type { GrantContext } from "#/grants/types.mjs";

describe("GrantContext.tokenBinding", () => {
	it("is undefined when not populated by middleware", () => {
		const ctx: GrantContext = {
			body: {},
			session: {},
			metadata: {},
			authenticatedClient: null,
		};
		expect(ctx.tokenBinding).toBeUndefined();
	});

	it("accepts a TokenBinding value when populated", () => {
		const ctx: GrantContext = {
			body: {},
			session: {},
			metadata: {},
			authenticatedClient: null,
			tokenBinding: { kind: "test", confirmation: { jkt: "abc" } },
		};
		expect(ctx.tokenBinding?.kind).toBe("test");
	});
});
