import { describe, expect, it } from "vitest";
import {
	AdapterFactoryError,
	AppConfigSchema,
	createAdapterFactory,
	createApp,
	createAsymmetricKeyStore,
	createKeyStoreFactory,
	createRepositoryFactories,
	createSymmetricKeyStore,
	formatObject,
	GrantRegistry,
	InMemoryClientRepository,
	InMemoryCodeRepository,
	InMemoryUserRepository,
	registerBuiltinKeyStores,
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

	it("exports createAdapterFactory function", () => {
		expect(typeof createAdapterFactory).toBe("function");
	});

	it("exports AdapterFactoryError class", () => {
		expect(AdapterFactoryError).toBeDefined();
		expect(typeof AdapterFactoryError).toBe("function");
	});

	it("exports createRepositoryFactories function", () => {
		expect(typeof createRepositoryFactories).toBe("function");
	});

	it("exports createSymmetricKeyStore function", () => {
		expect(typeof createSymmetricKeyStore).toBe("function");
	});

	it("exports createAsymmetricKeyStore function", () => {
		expect(typeof createAsymmetricKeyStore).toBe("function");
	});

	it("exports createKeyStoreFactory function", () => {
		expect(typeof createKeyStoreFactory).toBe("function");
	});

	it("exports registerBuiltinKeyStores function", () => {
		expect(typeof registerBuiltinKeyStores).toBe("function");
	});

	it("exports createApp function", () => {
		expect(typeof createApp).toBe("function");
	});

	it("exports formatObject function", () => {
		expect(typeof formatObject).toBe("function");
	});
});
