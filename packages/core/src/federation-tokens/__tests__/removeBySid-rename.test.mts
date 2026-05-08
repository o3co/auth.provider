/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

import { describe, expect, it } from "vitest";
import { createInMemoryFederationTokenStore } from "../adapters/memory.mjs";

describe("AS-3: FederationTokenStoreBase.deleteBySession → removeBySid (BREAKING rename)", () => {
	it("in-memory store exposes removeBySid", () => {
		const store = createInMemoryFederationTokenStore();
		expect("removeBySid" in store).toBe(true);
	});

	it("in-memory store no longer exposes deleteBySession", () => {
		const store = createInMemoryFederationTokenStore();
		expect("deleteBySession" in store).toBe(false);
	});

	it("removeBySid removes all federation entries for sid (functional parity with old deleteBySession)", async () => {
		const store = createInMemoryFederationTokenStore();
		const tokens = {
			accessToken: "at",
			refreshToken: "rt",
			idToken: "it",
			expiresAt: new Date("2026-04-22"),
		};
		await store.attach("sid-1", "google", tokens);
		await store.attach("sid-1", "github", tokens);
		await store.attach("sid-2", "google", tokens);
		await store.removeBySid("sid-1");
		expect(await store.get("sid-1", "google")).toBeNull();
		expect(await store.get("sid-1", "github")).toBeNull();
		expect(await store.get("sid-2", "google")).toEqual(tokens);
	});

	it("removeBySid is idempotent on absent sid", async () => {
		const store = createInMemoryFederationTokenStore();
		await expect(store.removeBySid("nope")).resolves.toBeUndefined();
	});
});
