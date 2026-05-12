import { describe, expect, it } from "vitest";
import * as core from "../index.mjs";

describe("core barrel — Wave 1 AccessTokenDenylist exports", () => {
	it("re-exports createMemoryAccessTokenDenylist", () => {
		expect(typeof core.createMemoryAccessTokenDenylist).toBe("function");
	});
	it("re-exports createAccessTokenDenylistFactory", () => {
		expect(typeof core.createAccessTokenDenylistFactory).toBe("function");
	});
	it("re-exports registerBuiltinAccessTokenDenylists", () => {
		expect(typeof core.registerBuiltinAccessTokenDenylists).toBe("function");
	});
	it("re-exports memoryAccessTokenDenylistModule", () => {
		expect(core.memoryAccessTokenDenylistModule).toBeDefined();
		expect(typeof core.memoryAccessTokenDenylistModule).toBe("object");
	});
});
