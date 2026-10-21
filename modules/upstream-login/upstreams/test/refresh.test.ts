import { describe, expect, it } from "vitest";
import { refreshedExpiry } from "../src/contract.ts";

describe("when a refreshed access token ends", () => {
	const held = { accessToken: "at-1", expiresAt: 1_000 };

	it("ends at the earlier of the two where the answer hands the same access token again", () => {
		expect(refreshedExpiry({ accessToken: "at-1", expiresAt: 5_000 }, held)).toBe(1_000);
		expect(refreshedExpiry({ accessToken: "at-1", expiresAt: 500 }, held)).toBe(500);
	});

	it("ends where the answer says for another token, or where none was held with an end", () => {
		expect(refreshedExpiry({ accessToken: "at-2", expiresAt: 5_000 }, held)).toBe(5_000);
		expect(
			refreshedExpiry({ accessToken: "at-1", expiresAt: 5_000 }, { accessToken: "at-1" }),
		).toBe(5_000);
		expect(refreshedExpiry({ accessToken: "at-1", expiresAt: 5_000 }, undefined)).toBe(5_000);
	});
});
