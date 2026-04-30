/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
import { describe, expect, it } from "vitest";
import { ChallengeStorageError } from "../errors.mjs";

describe("ChallengeStorageError", () => {
	it("carries reason 'duplicate' with default message and no cause own-property", () => {
		const err = new ChallengeStorageError({ reason: "duplicate" });
		expect(err).toBeInstanceOf(Error);
		expect(err.name).toBe("ChallengeStorageError");
		expect(err.reason).toBe("duplicate");
		expect(err.message).toBe("ChallengeStorageError: duplicate");
		expect(Object.hasOwn(err, "cause")).toBe(false);
	});

	it("explicit cause: undefined still does not materialise own-property cause", () => {
		// Defensive regression: if a future maintainer "simplifies" the constructor
		// to always pass `{ cause: opts.cause }`, this test fires immediately.
		const err = new ChallengeStorageError({ reason: "duplicate", cause: undefined });
		expect(Object.hasOwn(err, "cause")).toBe(false);
	});

	it("carries reason 'expired-at-issue' and propagates a custom message + cause", () => {
		const inner = new Error("PEXPIREAT in the past");
		const err = new ChallengeStorageError({
			reason: "expired-at-issue",
			message: "expiresAt <= now()",
			cause: inner,
		});
		expect(err.reason).toBe("expired-at-issue");
		expect(err.message).toBe("expiresAt <= now()");
		expect(err.cause).toBe(inner);
	});
});
