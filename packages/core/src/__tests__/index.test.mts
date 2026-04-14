import { describe, expect, it } from "vitest";
import {
	AppConfigSchema,
	createApp,
	createAsymmetricKeyStore,
	createDefaultFactories,
	createKeyStoreFromConfig,
	createSymmetricKeyStore,
	formatObject,
	GrantRegistry,
	InMemoryClientRepository,
	InMemoryCodeRepository,
	InMemoryUserRepository,
	RepositoryFactory,
} from "#/index.mjs";

describe("public API", () => {
	it("exports InMemoryClientRepository class", () => {
		expect(InMemoryClientRepository).toBeDefined();
		expect(typeof InMemoryClientRepository).toBe("function");
	});

	it("exports AppConfigSchema", () => {
		expect(AppConfigSchema).toBeDefined();
	});

	it("exports GrantRegistry class", () => {
		expect(GrantRegistry).toBeDefined();
		expect(typeof GrantRegistry).toBe("function");
	});

	it("exports InMemoryUserRepository class", () => {
		expect(InMemoryUserRepository).toBeDefined();
		expect(typeof InMemoryUserRepository).toBe("function");
	});

	it("exports InMemoryCodeRepository class", () => {
		expect(InMemoryCodeRepository).toBeDefined();
		expect(typeof InMemoryCodeRepository).toBe("function");
	});

	it("exports RepositoryFactory class", () => {
		expect(RepositoryFactory).toBeDefined();
		expect(typeof RepositoryFactory).toBe("function");
	});

	it("exports createDefaultFactories function", () => {
		expect(typeof createDefaultFactories).toBe("function");
	});

	it("exports createSymmetricKeyStore function", () => {
		expect(typeof createSymmetricKeyStore).toBe("function");
	});

	it("exports createAsymmetricKeyStore function", () => {
		expect(typeof createAsymmetricKeyStore).toBe("function");
	});

	it("exports createKeyStoreFromConfig function", () => {
		expect(typeof createKeyStoreFromConfig).toBe("function");
	});

	it("exports createApp function", () => {
		expect(typeof createApp).toBe("function");
	});

	it("exports formatObject function", () => {
		expect(typeof formatObject).toBe("function");
	});
});
