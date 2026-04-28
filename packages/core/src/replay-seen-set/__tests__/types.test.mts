/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
import { describe, expectTypeOf, it } from "vitest";
import type { ReplaySeenSet } from "../types.mjs";

describe("ReplaySeenSet type contract", () => {
	it("exposes readonly kind + markSeen/contains signatures", () => {
		expectTypeOf<ReplaySeenSet["kind"]>().toEqualTypeOf<string>();
		expectTypeOf<ReplaySeenSet["markSeen"]>().toEqualTypeOf<
			(scope: string, key: string, expiresAt: Date) => Promise<boolean>
		>();
		expectTypeOf<ReplaySeenSet["contains"]>().toEqualTypeOf<
			(scope: string, key: string) => Promise<boolean>
		>();
	});
});
