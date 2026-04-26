/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

import { describe, expect, it } from "vitest";
import {
	type SingleUseConsumeOutcome,
	type SingleUseMarkSeenOutcome,
	SingleUseTokenError,
} from "#/single-use-tokens/types.mjs";

describe("SingleUseConsumeOutcome", () => {
	it("narrows on the `outcome` discriminator", () => {
		const v: SingleUseConsumeOutcome = { outcome: "consumed" };
		if (v.outcome === "consumed") {
			expect(v.outcome).toBe("consumed");
		} else if (v.outcome === "unknown") {
			expect.fail("unreachable");
		} else if (v.outcome === "replayed") {
			expect.fail("unreachable");
		}
	});
});

describe("SingleUseMarkSeenOutcome", () => {
	it("narrows on the `outcome` discriminator", () => {
		const v: SingleUseMarkSeenOutcome = { outcome: "fresh" };
		if (v.outcome === "fresh") {
			expect(v.outcome).toBe("fresh");
		} else if (v.outcome === "replayed") {
			expect.fail("unreachable");
		}
	});
});

describe("SingleUseTokenError", () => {
	it("carries `reason` and a default message", () => {
		const e = new SingleUseTokenError({ reason: "duplicate" });
		expect(e.name).toBe("SingleUseTokenError");
		expect(e.reason).toBe("duplicate");
		expect(e.message).toContain("duplicate");
		expect(e).toBeInstanceOf(Error);
	});

	it("accepts a custom message", () => {
		const e = new SingleUseTokenError({
			reason: "expired-at-issue",
			message: "exp claim already past",
		});
		expect(e.reason).toBe("expired-at-issue");
		expect(e.message).toBe("exp claim already past");
	});
});
