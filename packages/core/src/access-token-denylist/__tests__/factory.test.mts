/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
import { describe, expect, it } from "vitest";
import {
	createAccessTokenDenylistFactory,
	registerBuiltinAccessTokenDenylists,
} from "../factory.mjs";

describe("AccessTokenDenylistFactory", () => {
	it("createAccessTokenDenylistFactory returns an empty factory", async () => {
		const factory = createAccessTokenDenylistFactory();
		await expect(factory.create({ type: "memory" })).rejects.toThrow();
	});

	it("registerBuiltinAccessTokenDenylists registers the 'memory' builder", async () => {
		const factory = createAccessTokenDenylistFactory();
		registerBuiltinAccessTokenDenylists(factory);
		const denylist = await factory.create({ type: "memory" });
		expect(denylist.kind).toBe("memory");
		expect(typeof denylist.add).toBe("function");
		expect(typeof denylist.has).toBe("function");
	});

	it("registering 'memory' twice throws AdapterFactoryError reason 'duplicate'", () => {
		const factory = createAccessTokenDenylistFactory();
		registerBuiltinAccessTokenDenylists(factory);
		expect(() => registerBuiltinAccessTokenDenylists(factory)).toThrow(
			expect.objectContaining({ name: "AdapterFactoryError", reason: "duplicate" }),
		);
	});
});
