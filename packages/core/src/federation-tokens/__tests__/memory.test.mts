/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

import { beforeEach, describe, expect, it } from "vitest";
import { createInMemoryFederationTokenStore } from "../adapters/memory.mjs";
import {
	type FederationTokenStore,
	type FederationTokens,
	type SupportsLock,
	supportsLock,
} from "../types.mjs";

describe("in-memory FederationTokenStore", () => {
	let store: FederationTokenStore;
	const tokens: FederationTokens = {
		accessToken: "at",
		refreshToken: "rt",
		idToken: "it",
		expiresAt: new Date("2026-04-22"),
		tokenType: undefined,
		scope: undefined,
		grantedScope: undefined,
	};

	beforeEach(() => {
		store = createInMemoryFederationTokenStore();
	});

	it("kind is 'memory'", () => {
		expect(store.kind).toBe("memory");
	});

	it("attach + get returns same tokens (including refreshToken in clear)", async () => {
		await store.attach("sid-1", "google", tokens);
		expect(await store.get("sid-1", "google")).toStrictEqual(tokens);
	});

	it.each([
		["attach", "attach"],
		["update", "update"],
	] as const)(
		"names every field it has no value for on %s, rather than leaving it out (#626)",
		async (_label, write) => {
			// Every optional field unset at once: the fixture above sets
			// `refreshToken` and `idToken`, so a copy that dropped either when
			// `undefined` would pass it.
			const bare: FederationTokens = {
				accessToken: "at",
				expiresAt: null,
				refreshToken: undefined,
				idToken: undefined,
				tokenType: undefined,
				scope: undefined,
				grantedScope: undefined,
			};
			if (write === "update") await store.attach("sid-1", "google", tokens);
			await store[write]("sid-1", "google", bare);
			expect(await store.get("sid-1", "google")).toStrictEqual(bare);
		},
	);

	it("keeps grantedScope through the defensive copy (#647)", async () => {
		// The copy is field by field, so a field it forgets is silently dropped —
		// and this one is the ceiling a refresh is bounded by.
		const withCeiling = { ...tokens, scope: "openid", grantedScope: "openid email" };
		await store.attach("sid-1", "google", withCeiling);
		expect(await store.get("sid-1", "google")).toStrictEqual(withCeiling);
	});

	it.each([
		["attach", "attach"],
		["update", "update"],
	] as const)("keeps tokenType through the defensive copy on %s (#645)", async (_label, write) => {
		// The same field-by-field copy, and here a forgotten field fails OPEN:
		// `POST /oauth/federation/:name/token` reads an absent `tokenType` as a
		// record written before #645 and answers Bearer, so a store that dropped
		// it would hand a DPoP-bound token on as a bearer one. `DPoP` rather than
		// `Bearer` so the assertion cannot pass by coincidence with the default.
		const senderConstrained = { ...tokens, tokenType: "DPoP" };
		if (write === "update") await store.attach("sid-1", "google", tokens);
		await store[write]("sid-1", "google", senderConstrained);
		expect((await store.get("sid-1", "google"))?.tokenType).toBe("DPoP");
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
			idToken: undefined,
			tokenType: undefined,
			scope: undefined,
			grantedScope: undefined,
		};
		await store.update("sid-1", "google", next);
		expect(await store.get("sid-1", "google")).toStrictEqual(next);
	});

	it("removeBySid removes all federation entries for sid", async () => {
		await store.attach("sid-1", "google", tokens);
		await store.attach("sid-1", "github", tokens);
		await store.attach("sid-2", "google", tokens);
		await store.removeBySid("sid-1");
		expect(await store.get("sid-1", "google")).toBeNull();
		expect(await store.get("sid-1", "github")).toBeNull();
		expect(await store.get("sid-2", "google")).toStrictEqual(tokens);
	});

	it("delete removes a single (sid, name) only", async () => {
		await store.attach("sid-1", "google", tokens);
		await store.attach("sid-1", "github", tokens);
		await store.delete("sid-1", "google");
		expect(await store.get("sid-1", "google")).toBeNull();
		expect(await store.get("sid-1", "github")).toStrictEqual(tokens);
	});

	it("removeBySid / delete are idempotent", async () => {
		await expect(store.removeBySid("nope")).resolves.toBeUndefined();
		await expect(store.delete("nope", "google")).resolves.toBeUndefined();
	});

	it("expiresAt=null round-trips as null (GitHub OAuth Apps classic)", async () => {
		await store.attach("sid-gh", "github", { ...tokens, expiresAt: null });
		const round = await store.get("sid-gh", "github");
		expect(round?.expiresAt).toBeNull();
	});

	it("implements SupportsLock capability", async () => {
		const s = createInMemoryFederationTokenStore();
		expect(supportsLock(s)).toBe(true);
		const r = await (s as FederationTokenStore & SupportsLock).acquireLock({
			sid: "s",
			federationName: "google",
		});
		expect(r.acquired).toBe(true);
		if (r.acquired) await r.release();
	});
});
