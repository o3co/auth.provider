import { describe, expect, it } from "vitest";

describe("a suite [rfc7009-2-a]", () => {
	it("passes [rfc7009-2-b]", () => expect(1).toBe(1));
	it("fails [rfc7009-2-c]", () => expect(1).toBe(2));
	it("is left out", (context) => context.skip("excused: adaptation"));
});
