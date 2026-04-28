/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
import { describe, expect, expectTypeOf, it } from "vitest";
import type { ChallengeStorageErrorReason } from "../errors.mjs";
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

describe("ChallengeStorageErrorReason type contract", () => {
	it("is a closed discriminated union of exactly two literals", () => {
		expectTypeOf<ChallengeStorageErrorReason>().toEqualTypeOf<"duplicate" | "expired-at-issue">();
	});

	it("permits exhaustive switch via narrowing (compile-time only)", () => {
		// Type-level fixture — at runtime this asserts nothing, but the
		// exhaustiveness assertion below fails to type-check if the union
		// grows without updating the switch.
		const exhaust = (reason: ChallengeStorageErrorReason): string => {
			switch (reason) {
				case "duplicate":
					return "dup";
				case "expired-at-issue":
					return "exp";
				default: {
					const _never: never = reason;
					return _never;
				}
			}
		};
		expect(exhaust("duplicate")).toBe("dup");
	});
});
