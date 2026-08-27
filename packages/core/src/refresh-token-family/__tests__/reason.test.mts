/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
import { describe, expect, it } from "vitest";
import { withReason } from "../reason.mjs";

describe("withReason", () => {
	it("produces an empty object for undefined, so the spread adds no key", () => {
		expect(Object.keys(withReason(undefined))).toEqual([]);
		expect("reason" in withReason(undefined)).toBe(false);
		// The property the whole helper exists for: spreading must leave the
		// target untouched, not stamp `reason: undefined` onto it.
		expect("reason" in { outcome: "aborted", ...withReason(undefined) }).toBe(false);
	});

	it("carries the reason through when one was supplied", () => {
		expect(withReason("replay-detected-family-revoked")).toStrictEqual({
			reason: "replay-detected-family-revoked",
		});
		expect("reason" in { outcome: "aborted", ...withReason("x") }).toBe(true);
	});

	it("treats the empty string as a supplied reason, not as absence", () => {
		// `""` is falsy, so a truthiness check here would silently drop a
		// caller-chosen reason. The contract keys off `undefined` alone.
		expect(withReason("")).toStrictEqual({ reason: "" });
		expect("reason" in withReason("")).toBe(true);
	});
});
