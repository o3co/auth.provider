import { describe, expect, it } from "vitest";
import {
	AppConfigSchema,
	createAsymmetricKeyStore,
	createDefaultFactories,
	createGoogleProvider,
	createKeyStoreFromConfig,
	createPassport,
	createRouter,
	createSymmetricKeyStore,
	FederationRegistry,
	GrantRegistry,
	InMemoryClientRepository,
	InMemoryCodeRepository,
	InMemoryUserRepository,
	RepositoryFactory,
} from "../index.mjs";

describe("public API", () => {
	it("exports InMemoryClientRepository class", () => {
		expect(InMemoryClientRepository).toBeDefined();
		expect(typeof InMemoryClientRepository).toBe("function");
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
});
