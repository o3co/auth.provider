/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

import { beforeEach, describe, expect, it } from "vitest";
import { createInMemoryUserSessionStore } from "../adapters/memory.mjs";
import type { UserSessionStoreBase } from "../types.mjs";

describe("in-memory UserSessionStore", () => {
	let store: UserSessionStoreBase;
	beforeEach(() => {
		store = createInMemoryUserSessionStore();
	});

	const baseInput = {
		sid: "sid-1",
		sub: "user-1",
		authTime: new Date("2026-04-21T00:00:00Z"),
		expiresAt: new Date("2026-04-22T00:00:00Z"),
		claims: { email: "a@b.com" },
	};

	it("kind is 'memory'", () => {
		expect(store.kind).toBe("memory");
	});

	it("create + get returns the session with defaulted arrays", async () => {
		await store.create(baseInput);
		const s = await store.get("sid-1");
		expect(s).toMatchObject({
			sid: "sid-1",
			sub: "user-1",
			federations: [],
			activeRPs: [],
			familyIds: [],
			claims: { email: "a@b.com" },
		});
		expect(s?.createdAt).toBeInstanceOf(Date);
	});

	it("get returns null for unknown sid", async () => {
		expect(await store.get("missing")).toBeNull();
	});

	it("get returns null for expired session (GC on read)", async () => {
		await store.create({ ...baseInput, expiresAt: new Date(Date.now() - 1000) });
		expect(await store.get("sid-1")).toBeNull();
	});

	it("registerRP appends then replaces duplicates by clientId", async () => {
		await store.create(baseInput);
		await store.registerRP("sid-1", { clientId: "rp-1", registeredAt: new Date() });
		await store.registerRP("sid-1", {
			clientId: "rp-1",
			backchannelLogoutUri: "https://rp/bc",
			registeredAt: new Date(),
		});
		const s = await store.get("sid-1");
		expect(s?.activeRPs).toHaveLength(1);
		expect(s?.activeRPs[0]?.backchannelLogoutUri).toBe("https://rp/bc");
	});

	it("linkFamily appends without duplicates", async () => {
		await store.create(baseInput);
		await store.linkFamily("sid-1", "fam-1");
		await store.linkFamily("sid-1", "fam-1");
		await store.linkFamily("sid-1", "fam-2");
		const s = await store.get("sid-1");
		expect(s?.familyIds).toEqual(["fam-1", "fam-2"]);
	});

	it("updateClaims merges, overwriting existing keys", async () => {
		await store.create(baseInput);
		await store.updateClaims("sid-1", { email: "b@c.com", name: "Alice" });
		const s = await store.get("sid-1");
		expect(s?.claims).toEqual({ email: "b@c.com", name: "Alice" });
	});

	it("removeFederation is idempotent", async () => {
		await store.create({ ...baseInput, federations: ["google", "github"] });
		await store.removeFederation("sid-1", "google");
		await store.removeFederation("sid-1", "google");
		const s = await store.get("sid-1");
		expect(s?.federations).toEqual(["github"]);
	});

	it("delete removes the record (does NOT cascade)", async () => {
		await store.create(baseInput);
		await store.delete("sid-1");
		expect(await store.get("sid-1")).toBeNull();
	});

	it("operations on missing sid are no-ops for idempotent ones", async () => {
		await expect(
			store.registerRP("missing", { clientId: "rp", registeredAt: new Date() }),
		).resolves.toBeUndefined();
		await expect(store.linkFamily("missing", "fam")).resolves.toBeUndefined();
		await expect(store.updateClaims("missing", { email: "x" })).resolves.toBeUndefined();
		await expect(store.removeFederation("missing", "google")).resolves.toBeUndefined();
		await expect(store.delete("missing")).resolves.toBeUndefined();
	});

	it("create throws on duplicate sid (caller must avoid re-use)", async () => {
		await store.create(baseInput);
		await expect(store.create(baseInput)).rejects.toThrow(/already exists/);
	});

	it("create succeeds when an expired entry exists for the same sid (GC before duplicate check)", async () => {
		// Put an expired entry in the map first.
		await store.create({ ...baseInput, expiresAt: new Date(Date.now() - 1000) });
		// DO NOT call store.get() here — it would GC the expired entry via
		// readLive() and then the duplicate-check inside create() would trivially
		// pass under any implementation (including the old `sessions.has()` check).
		// We want the regression guarantee to rest on create() itself invoking
		// readLive() before deciding whether a duplicate exists.
		await expect(
			store.create({ ...baseInput, expiresAt: new Date(Date.now() + 3600_000) }),
		).resolves.toBeUndefined();
		const s = await store.get("sid-1");
		expect(s).not.toBeNull();
		// And the fresh record's expiresAt is in the future (not the stale past one).
		expect(s?.expiresAt.getTime()).toBeGreaterThan(Date.now());
	});
});
