/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

import { beforeEach, describe, expect, it } from "vitest";
import { createInMemoryFederationTokenStore } from "../adapters/memory.mjs";
import {
	type FederationTokenStoreBase,
	type FederationTokens,
	type SupportsLock,
	supportsLock,
} from "../types.mjs";

describe("in-memory FederationTokenStore", () => {
	let store: FederationTokenStoreBase;
	const tokens: FederationTokens = {
		accessToken: "at",
		refreshToken: "rt",
		idToken: "it",
		expiresAt: new Date("2026-04-22"),
	};

	beforeEach(() => {
		store = createInMemoryFederationTokenStore();
	});

	it("kind is 'memory'", () => {
		expect(store.kind).toBe("memory");
	});

	it("attach + get returns same tokens (including refreshToken in clear)", async () => {
		await store.attach("sid-1", "google", tokens);
		expect(await store.get("sid-1", "google")).toEqual(tokens);
	});

	it("get returns null for missing (sid, name)", async () => {
		expect(await store.get("sid-1", "google")).toBeNull();
		await store.attach("sid-1", "google", tokens);
		expect(await store.get("sid-1", "github")).toBeNull();
	});

	it("update replaces atomically", async () => {
		await store.attach("sid-1", "google", tokens);
		const next: FederationTokens = {
			accessToken: "at-new",
			refreshToken: "rt-new",
			expiresAt: new Date("2026-04-23"),
		};
		await store.update("sid-1", "google", next);
		expect(await store.get("sid-1", "google")).toEqual(next);
	});

	it("deleteBySession removes all federation entries for sid", async () => {
		await store.attach("sid-1", "google", tokens);
		await store.attach("sid-1", "github", tokens);
		await store.attach("sid-2", "google", tokens);
		await store.deleteBySession("sid-1");
		expect(await store.get("sid-1", "google")).toBeNull();
		expect(await store.get("sid-1", "github")).toBeNull();
		expect(await store.get("sid-2", "google")).toEqual(tokens);
	});

	it("delete removes a single (sid, name) only", async () => {
		await store.attach("sid-1", "google", tokens);
		await store.attach("sid-1", "github", tokens);
		await store.delete("sid-1", "google");
		expect(await store.get("sid-1", "google")).toBeNull();
		expect(await store.get("sid-1", "github")).toEqual(tokens);
	});

	it("deleteBySession / delete are idempotent", async () => {
		await expect(store.deleteBySession("nope")).resolves.toBeUndefined();
		await expect(store.delete("nope", "google")).resolves.toBeUndefined();
	});

	it("implements SupportsLock capability", async () => {
		const s = createInMemoryFederationTokenStore();
		expect(supportsLock(s)).toBe(true);
		const r = await (s as FederationTokenStoreBase & SupportsLock).acquireLock({
			sid: "s",
			federationName: "google",
		});
		expect(r.acquired).toBe(true);
		if (r.acquired) await r.release();
	});
});
