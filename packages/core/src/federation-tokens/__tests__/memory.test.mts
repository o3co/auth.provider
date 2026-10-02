/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

import { beforeEach, describe, expect, it } from "vitest";
import { isStoreGeneration } from "../../adapters/conditionalWrite.mjs";
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
		obtainedAt: undefined,
	};

	/** A replace of the live record of (sid-1, google), at its current generation. */
	const replace = async (next: FederationTokens): Promise<void> => {
		const read = await store.getVersioned("sid-1", "google");
		if (read === null) throw new Error("sid-1/google is not live");
		const answer = await store.replaceIf("sid-1", "google", read.generation, next);
		if (answer.outcome !== "updated") throw new Error(answer.outcome);
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
		["replaceIf", "replaceIf"],
	] as const)(
		"names every field it has no value for on %s, rather than leaving it out",
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
				obtainedAt: undefined,
			};
			await store.attach("sid-1", "google", write === "attach" ? bare : tokens);
			if (write === "replaceIf") await replace(bare);
			expect(await store.get("sid-1", "google")).toStrictEqual(bare);
		},
	);

	it("keeps grantedScope through the defensive copy", async () => {
		// The copy is field by field, so a field it forgets is silently dropped —
		// and this one is the ceiling a refresh is bounded by.
		const withCeiling = { ...tokens, scope: "openid", grantedScope: "openid email" };
		await store.attach("sid-1", "google", withCeiling);
		expect(await store.get("sid-1", "google")).toStrictEqual(withCeiling);
	});

	it.each([
		["attach", "attach"],
		["replaceIf", "replaceIf"],
	] as const)("keeps tokenType through the defensive copy on %s", async (_label, write) => {
		// The same field-by-field copy, and here a forgotten field fails OPEN:
		// `POST /oauth/federation/:name/token` reads an absent `tokenType` as a
		// record written before the field existed and answers Bearer, so a store
		// that dropped it would hand a DPoP-bound token on as a bearer one.
		// `DPoP` rather than `Bearer` so the assertion cannot pass by coincidence
		// with the default.
		const senderConstrained = { ...tokens, tokenType: "DPoP" };
		await store.attach("sid-1", "google", write === "attach" ? senderConstrained : tokens);
		if (write === "replaceIf") await replace(senderConstrained);
		expect((await store.get("sid-1", "google"))?.tokenType).toBe("DPoP");
	});

	describe("obtainedAt", () => {
		const obtainedAt = new Date("2026-04-21T23:00:00.000Z");

		it.each([
			["attach", "attach"],
			["replaceIf", "replaceIf"],
		] as const)("round-trips it on %s", async (_label, write) => {
			const dated: FederationTokens = { ...tokens, obtainedAt };
			await store.attach("sid-1", "google", write === "attach" ? dated : tokens);
			if (write === "replaceIf") await replace(dated);
			const got = await store.get("sid-1", "google");
			expect(got).toStrictEqual(dated);
			expect(got?.obtainedAt).toBeInstanceOf(Date);
		});

		it("names it as undefined when the record has none", async () => {
			await store.attach("sid-1", "google", tokens);
			const got = await store.get("sid-1", "google");
			expect(got).not.toBeNull();
			expect(Object.hasOwn(got as object, "obtainedAt")).toBe(true);
			expect(got?.obtainedAt).toBeUndefined();
		});

		it("drops its value when a replace writes a dated record over with an undated one", async () => {
			await store.attach("sid-1", "google", { ...tokens, obtainedAt });
			await replace(tokens);
			const got = await store.get("sid-1", "google");
			expect(got).toStrictEqual(tokens);
			expect(got?.obtainedAt).toBeUndefined();
		});

		it("is not moved by a later change to the caller's Date", async () => {
			const callers = new Date(obtainedAt.getTime());
			await store.attach("sid-1", "google", { ...tokens, obtainedAt: callers });
			callers.setTime(0);
			expect((await store.get("sid-1", "google"))?.obtainedAt).toStrictEqual(obtainedAt);
		});

		it("is not moved by a change to a Date that get handed back", async () => {
			await store.attach("sid-1", "google", { ...tokens, obtainedAt });
			(await store.get("sid-1", "google"))?.obtainedAt?.setTime(0);
			expect((await store.get("sid-1", "google"))?.obtainedAt).toStrictEqual(obtainedAt);
		});
	});

	it("get returns null for missing (sid, name)", async () => {
		expect(await store.get("sid-1", "google")).toBeNull();
		await store.attach("sid-1", "google", tokens);
		expect(await store.get("sid-1", "github")).toBeNull();
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

	describe("conditional members", () => {
		const live = async (sid: string, name: string) => {
			const read = await store.getVersioned(sid, name);
			if (read === null) throw new Error(`${sid}/${name} is not live`);
			return read;
		};

		it("getVersioned answers null for an absent record, and a copy at a generation for a live one", async () => {
			expect(await store.getVersioned("sid-1", "google")).toBeNull();
			await store.attach("sid-1", "google", tokens);
			const read = await live("sid-1", "google");
			expect(read.value).toStrictEqual(tokens);
			expect(isStoreGeneration(read.generation)).toBe(true);
			// A copy: changing it changes nothing stored.
			(read.value as { accessToken: string }).accessToken = "changed";
			expect((await store.get("sid-1", "google"))?.accessToken).toBe("at");
		});

		it("every write moves the generation, a byte-identical one included", async () => {
			await store.attach("sid-1", "google", tokens);
			const first = (await live("sid-1", "google")).generation;
			await replace(tokens);
			const second = (await live("sid-1", "google")).generation;
			await store.attach("sid-1", "google", tokens);
			const third = (await live("sid-1", "google")).generation;
			expect(new Set([first, second, third]).size).toBe(3);
		});

		it("replaceIf answers missing for an absent record, conflict at another generation, and updated at the current one", async () => {
			await store.attach("sid-1", "google", tokens);
			const read = await live("sid-1", "google");
			expect(await store.replaceIf("sid-1", "okta", read.generation, tokens)).toEqual({
				outcome: "missing",
			});
			expect(await store.getVersioned("sid-1", "okta")).toBeNull();

			const next = { ...tokens, accessToken: "at-2" };
			const replaced = await store.replaceIf("sid-1", "google", read.generation, next);
			if (replaced.outcome !== "updated") throw new Error(replaced.outcome);
			expect(replaced.generation).not.toBe(read.generation);
			expect(await live("sid-1", "google")).toStrictEqual({
				value: next,
				generation: replaced.generation,
			});

			expect(await store.replaceIf("sid-1", "google", read.generation, tokens)).toEqual({
				outcome: "conflict",
			});
			expect((await store.get("sid-1", "google"))?.accessToken).toBe("at-2");
		});

		it("removeIf answers missing for an absent record, conflict at another generation, and removed at the current one", async () => {
			await store.attach("sid-1", "google", tokens);
			const read = await live("sid-1", "google");
			expect(await store.removeIf("sid-1", "okta", read.generation)).toEqual({
				outcome: "missing",
			});
			await store.attach("sid-1", "google", tokens);
			expect(await store.removeIf("sid-1", "google", read.generation)).toEqual({
				outcome: "conflict",
			});
			expect(await store.get("sid-1", "google")).not.toBeNull();

			const current = await live("sid-1", "google");
			expect(await store.removeIf("sid-1", "google", current.generation)).toEqual({
				outcome: "removed",
			});
			expect(await store.get("sid-1", "google")).toBeNull();
			expect(await store.removeIf("sid-1", "google", current.generation)).toEqual({
				outcome: "missing",
			});
		});
	});
});
