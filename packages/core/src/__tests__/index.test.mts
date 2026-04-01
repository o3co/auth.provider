import { describe, expect, it } from "vitest";
import {
	AppConfigSchema,
	createPassport,
	createRouter,
	StaticClientRepository,
} from "../index.mjs";

describe("public API", () => {
	it("exports StaticClientRepository class", () => {
		expect(StaticClientRepository).toBeDefined();
		expect(typeof StaticClientRepository).toBe("function");
	});

	it("exports AppConfigSchema", () => {
		expect(AppConfigSchema).toBeDefined();
	});

	it("exports createRouter function", () => {
		expect(typeof createRouter).toBe("function");
	});

	it("exports createPassport function", () => {
		expect(typeof createPassport).toBe("function");
	});
});
