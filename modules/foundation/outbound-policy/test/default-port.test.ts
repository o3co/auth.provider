import { expect, it } from "vitest";
import { defaultPortOf } from "../src/policy.ts";

it("answers 443 for an https URL naming no port, 80 for a plain http one", () => {
	expect(defaultPortOf(new URL("https://example.com/").protocol)).toBe(443);
	expect(defaultPortOf(new URL("http://example.com/").protocol)).toBe(80);
});
