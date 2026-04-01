import { describe, expect, it } from "vitest";
import {
	AppConfigSchema,
	createGoogleProvider,
	createPassport,
	createRouter,
	FederationRegistry,
	GrantRegistry,
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

	it("exports GrantRegistry class", () => {
		expect(GrantRegistry).toBeDefined();
		expect(typeof GrantRegistry).toBe("function");
	});

	it("exports FederationRegistry class", () => {
		expect(FederationRegistry).toBeDefined();
		expect(typeof FederationRegistry).toBe("function");
	});

	it("exports createGoogleProvider function", () => {
		expect(typeof createGoogleProvider).toBe("function");
	});
});
