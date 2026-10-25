import { afterAll, describe, expect, it } from "vitest";

describe("a suite whose hook fails", () => {
	afterAll(() => {
		throw new Error("the hook fails");
	});
	it("passes alone [rfc7009-2-d]", () => expect(1).toBe(1));
});
