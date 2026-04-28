/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
import { describe, expectTypeOf, it } from "vitest";
import type { Challenge, ChallengeStore } from "../types.mjs";

describe("ChallengeStore type contract", () => {
	it("Challenge has readonly expiresAt: Date", () => {
		expectTypeOf<Challenge>().toEqualTypeOf<{ readonly expiresAt: Date }>();
	});

	it("ChallengeStore exposes readonly kind + issue/find/consume signatures", () => {
		expectTypeOf<ChallengeStore["kind"]>().toEqualTypeOf<string>();
		expectTypeOf<ChallengeStore["issue"]>().toEqualTypeOf<
			(scope: string, value: string, expiresAt: Date) => Promise<void>
		>();
		expectTypeOf<ChallengeStore["find"]>().toEqualTypeOf<
			(scope: string, value: string) => Promise<Challenge | null>
		>();
		expectTypeOf<ChallengeStore["consume"]>().toEqualTypeOf<
			(scope: string, value: string) => Promise<boolean>
		>();
	});
});
