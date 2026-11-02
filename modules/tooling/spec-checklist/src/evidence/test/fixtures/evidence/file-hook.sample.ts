import { afterAll, expect, it } from "vitest";

afterAll(() => {
	throw new Error("the file's hook fails");
});
it("passes in a file whose hook fails [rfc7009-2-e]", () => expect(1).toBe(1));
