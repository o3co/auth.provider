/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

import { describe, expect, it } from "vitest";
import { createInProcessLock } from "../memory.mjs";

describe("in-process FederationToken lock", () => {
	it("acquires when no holder", async () => {
		const lock = createInProcessLock();
		const r = await lock.acquireLock({ sid: "s", federationName: "google" });
		expect(r.acquired).toBe(true);
		if (r.acquired) await r.release();
	});

	it("blocks a second acquire until the first releases (within waitForMs)", async () => {
		const lock = createInProcessLock();
		const a = await lock.acquireLock({ sid: "s", federationName: "google", ttlMs: 200 });
		expect(a.acquired).toBe(true);
		setTimeout(() => {
			if (a.acquired) a.release();
		}, 30);
		const b = await lock.acquireLock({ sid: "s", federationName: "google", waitForMs: 500 });
		expect(b.acquired).toBe(true);
		if (b.acquired) await b.release();
	});

	it("returns acquired: false, reason: timeout when waitForMs elapses with holder still active", async () => {
		const lock = createInProcessLock();
		const a = await lock.acquireLock({ sid: "s", federationName: "google", ttlMs: 5_000 });
		expect(a.acquired).toBe(true);
		const b = await lock.acquireLock({ sid: "s", federationName: "google", waitForMs: 100 });
		expect(b.acquired).toBe(false);
		if (!b.acquired) expect(b.reason).toBe("timeout");
		if (a.acquired) await a.release();
	});

	it("TTL expiry allows next acquire without explicit release (stale holder)", async () => {
		const lock = createInProcessLock();
		await lock.acquireLock({ sid: "s", federationName: "google", ttlMs: 50 });
		await new Promise((r) => setTimeout(r, 80));
		const b = await lock.acquireLock({ sid: "s", federationName: "google", waitForMs: 100 });
		expect(b.acquired).toBe(true);
		if (b.acquired) await b.release();
	});

	it("release after TTL expiry does not delete a re-acquired lock (ownership-token defense)", async () => {
		const lock = createInProcessLock();
		const a = await lock.acquireLock({ sid: "s", federationName: "google", ttlMs: 30 });
		expect(a.acquired).toBe(true);
		await new Promise((r) => setTimeout(r, 60)); // TTL expires
		const b = await lock.acquireLock({ sid: "s", federationName: "google", ttlMs: 5_000 });
		expect(b.acquired).toBe(true);
		// Caller A resumes and releases — must NOT delete B's entry.
		if (a.acquired) await a.release();
		// B's lock should still block a third acquire.
		const c = await lock.acquireLock({ sid: "s", federationName: "google", waitForMs: 50 });
		expect(c.acquired).toBe(false);
		if (b.acquired) await b.release();
	});

	it("separate (sid, federationName) pairs don't block each other", async () => {
		const lock = createInProcessLock();
		const a = await lock.acquireLock({ sid: "s1", federationName: "google", ttlMs: 5_000 });
		expect(a.acquired).toBe(true);
		const b = await lock.acquireLock({
			sid: "s1",
			federationName: "github",
			ttlMs: 1_000,
			waitForMs: 100,
		});
		const c = await lock.acquireLock({
			sid: "s2",
			federationName: "google",
			ttlMs: 1_000,
			waitForMs: 100,
		});
		expect(b.acquired).toBe(true);
		expect(c.acquired).toBe(true);
		if (a.acquired) await a.release();
		if (b.acquired) await b.release();
		if (c.acquired) await c.release();
	});
});
