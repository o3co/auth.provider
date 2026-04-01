import { describe, it, expect } from "vitest";
import {
	StaticClientRepository,
	AppConfigSchema,
	createRouter,
	createPassport,
} from "../index.mjs";
import type {
	ClientRepository,
	UserRepository,
	CodeRepository,
	PublicClient,
	Client,
	User,
	Code,
	CodeData,
	AppConfig,
	GrantFactory,
	GrantDependencies,
	GrantHandler,
	GrantContext,
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
