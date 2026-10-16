import { timingSafeEqual } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { sameSecret } from "../src/contract.ts";

vi.mock("node:crypto", async (original) => {
	const crypto = await original<typeof import("node:crypto")>();
	return { ...crypto, timingSafeEqual: vi.fn(crypto.timingSafeEqual) };
});

describe("sameSecret", () => {
	it("answers whether two secrets hold the same bytes, strings taken as UTF-8", () => {
		expect(sameSecret("s3cret-ä", "s3cret-ä")).toBe(true);
		expect(sameSecret("s3cret-a", "s3cret-b")).toBe(false);
		expect(sameSecret("ä", Buffer.from("ä", "utf8"))).toBe(true);
		expect(sameSecret(new Uint8Array([1, 2]), new Uint8Array([1, 3]))).toBe(false);
		expect(sameSecret("", "")).toBe(true);
	});

	it("answers false for secrets of different byte lengths, also when the characters count the same", () => {
		expect(sameSecret("abc", "abcd")).toBe(false);
		expect(sameSecret("a", "ä")).toBe(false);
		expect(sameSecret("", "a")).toBe(false);
	});

	it("compares in constant time only secrets of the same byte length", () => {
		vi.mocked(timingSafeEqual).mockClear();
		sameSecret("abc", "abcd");
		expect(timingSafeEqual).not.toHaveBeenCalled();
		sameSecret("abc", "abd");
		expect(timingSafeEqual).toHaveBeenCalledOnce();
	});
});
