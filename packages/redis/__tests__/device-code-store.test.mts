/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

/**
 * Redis-backed `DeviceCodeStore` against the shared conformance suite, on a
 * real Redis.
 *
 * The suite's "two polls racing for the same approval" case needs the real
 * server: a fake answering from a `Map` cannot tell a Lua script's atomicity
 * from a round trip's. The cases below pin what is Redis-specific: the key
 * layout Cluster relies on, the TTL, and that `expired` is answered from the
 * timestamp.
 */

import { Redis } from "ioredis";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createRedisDeviceCodeStore } from "#/device-code-store.mjs";
import { makeIoredisClients } from "#/ioredis.mjs";
import { runDeviceCodeStoreContract } from "./adapters.device-code-store.contract.mjs";
import { testRedis } from "./support/redis.mjs";

let raw: Redis;
let keyCounter = 0;

beforeAll(async () => {
	const at = await testRedis();
	raw = new Redis(at);
});

afterAll(async () => {
	await raw?.quit();
});

/** Per-test prefix isolation, so the racing cases never share a record. */
const freshPrefix = (): string => {
	keyCounter += 1;
	return `devauth:test-${keyCounter}:`;
};

const storeAt = (keyPrefix: string) =>
	createRedisDeviceCodeStore({
		client: makeIoredisClients(raw).deviceCodeStoreClient,
		keyPrefix,
	});

runDeviceCodeStoreContract("redis", {
	create: () => storeAt(freshPrefix()),
});

const NOW = 1_800_000_000_000;

const seed = {
	deviceCode: "dc-aaaaaaaaaaaaaaaaaaaa",
	userCode: "BCDFGHJK",
	clientId: "tv-app",
	requestedScope: ["openid", "profile"] as readonly string[],
	expiresAtMs: NOW + 10 * 60_000,
	intervalSeconds: 5,
};

describe("createRedisDeviceCodeStore — what is Redis-specific", () => {
	it('declares kind "redis"', () => {
		expect(storeAt(freshPrefix()).kind).toBe("redis");
	});

	it("keys the record and the user-code index under one shared hash tag", async () => {
		// Redis Cluster routes a script by the slot its keys hash to, and the
		// two keys here are derived from independent random values. Without a
		// tag they would land on different slots and `approve` — which reaches
		// the record through the index — could not touch both in one script.
		// The tag is a constant, so every device authorization shares a slot;
		// that concentration is the documented trade.
		const prefix = freshPrefix();
		await storeAt(prefix).create(seed);

		const keys = (await raw.keys(`${prefix}*`)).sort();
		expect(keys).toEqual([
			`${prefix}{devauth}:code:${seed.deviceCode}`,
			`${prefix}{devauth}:user:${seed.userCode}`,
		]);
	});

	it("refuses a finite expiry past the Date range before the script writes anything", async () => {
		// `1e20` is sent as a decimal PEXPIREAT Redis cannot take, and `1e21` as
		// `1e+21`: either fails only after the script has written the record and
		// its index, which would leave both with no TTL at all.
		for (const expiresAtMs of [8_640_000_000_000_001, 1e20, 1e21]) {
			const prefix = freshPrefix();
			await expect(storeAt(prefix).create({ ...seed, expiresAtMs })).rejects.toThrow(RangeError);
			expect(await raw.keys(`${prefix}*`)).toEqual([]);
		}
	});

	it("gives both keys the authorization's own expiry as their TTL", async () => {
		// Expired records are reclaimed by Redis rather than swept. Both keys
		// carry the same absolute deadline, so the index cannot outlive the
		// record it points at.
		const prefix = freshPrefix();
		await storeAt(prefix).create(seed);

		expect(await raw.pexpiretime(`${prefix}{devauth}:code:${seed.deviceCode}`)).toBe(
			seed.expiresAtMs,
		);
		expect(await raw.pexpiretime(`${prefix}{devauth}:user:${seed.userCode}`)).toBe(
			seed.expiresAtMs,
		);
	});

	it("answers expired from expiresAtMs, not from the TTL", async () => {
		// The port's contract is the timestamp the caller passes, not the key's
		// lifetime. The fixture's expiry is years away on the server's clock,
		// so the record is still resident when the caller's clock says it has
		// passed — and the answer must still be `expired`, with the record
		// reclaimed rather than left for the TTL.
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		await store.create(seed);
		const codeKey = `${prefix}{devauth}:code:${seed.deviceCode}`;
		const userKey = `${prefix}{devauth}:user:${seed.userCode}`;
		expect(await raw.exists(codeKey, userKey)).toBe(2);

		expect(await store.poll(seed.deviceCode, seed.expiresAtMs + 1)).toEqual({
			status: "expired",
		});
		expect(await raw.exists(codeKey, userKey)).toBe(0);
	});

	it("consumes the user-code index together with the approved record", async () => {
		// Consuming the record but not the index would leave a user code that
		// resolves to nothing — reported as a collision to the next `create`
		// that draws it, for a record nothing can reach.
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		await store.create(seed);
		await store.approve({ userCode: seed.userCode, subject: "user-1", nowMs: NOW });

		expect((await store.poll(seed.deviceCode, NOW + 10_000)).status).toBe("approved");
		expect(await raw.exists(`${prefix}{devauth}:user:${seed.userCode}`)).toBe(0);
	});

	it("round-trips a record with no requestedScope and grants nothing on approval", async () => {
		// The memory adapter's semantics for a request with no scope: it reads
		// back as `requestedScope: undefined` — the key named, as every field of
		// the record is — and an approval of a scopeless request grants
		// the empty set rather than failing or inventing one.
		const store = storeAt(freshPrefix());
		await store.create({ ...seed, requestedScope: undefined });

		const found = await store.findPendingByUserCode(seed.userCode, NOW);
		expect(found).not.toBeNull();
		expect(found).toHaveProperty("requestedScope", undefined);

		const decided = await store.approve({
			userCode: seed.userCode,
			subject: "user-1",
			grantedScope: ["openid"],
			nowMs: NOW,
		});
		expect(decided.status).toBe("ok");
		if (decided.status === "ok") expect(decided.authorization.grantedScope).toEqual([]);
	});

	it("narrows a supplied grantedScope to what was requested, in the caller's order", async () => {
		const store = storeAt(freshPrefix());
		await store.create({ ...seed, requestedScope: ["openid", "profile", "email"] });

		const decided = await store.approve({
			userCode: seed.userCode,
			subject: "user-1",
			grantedScope: ["email", "admin", "openid"],
			nowMs: NOW,
		});
		expect(decided.status).toBe("ok");
		if (decided.status === "ok") {
			expect(decided.authorization.grantedScope).toEqual(["email", "openid"]);
		}
	});
});

describe("redis DeviceCodeStore — the approving session's amr and authentication time", () => {
	const keysAt = (prefix: string) => ({
		codeKey: `${prefix}{devauth}:code:${seed.deviceCode}`,
	});

	it("writes neither field for an approval handed neither, and each as handed otherwise", async () => {
		const absentPrefix = freshPrefix();
		const absent = storeAt(absentPrefix);
		await absent.create(seed);
		await absent.approve({ userCode: seed.userCode, subject: "user-1", nowMs: NOW });
		const absentFields = await raw.hkeys(keysAt(absentPrefix).codeKey);
		expect(absentFields).toContain("approvedAtMs");
		expect(absentFields).not.toContain("amr");
		expect(absentFields).not.toContain("authTimeMs");

		const presentPrefix = freshPrefix();
		const present = storeAt(presentPrefix);
		await present.create(seed);
		await present.approve({
			userCode: seed.userCode,
			subject: "user-1",
			nowMs: NOW,
			amr: ["pwd", "mfa"],
			authTime: new Date(NOW - 60_000),
		});
		const { codeKey } = keysAt(presentPrefix);
		expect(await raw.hget(codeKey, "amr")).toBe('["pwd","mfa"]');
		expect(await raw.hget(codeKey, "authTimeMs")).toBe(String(NOW - 60_000));
	});

	it("reads a record approved without the two fields, as by an older release, as holding neither", async () => {
		// A replica not yet upgraded runs its own approval script, which writes
		// neither field; the record is still a whole one, with both keys named.
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		await store.create(seed);
		await raw.hset(keysAt(prefix).codeKey, {
			status: "approved",
			subject: "user-1",
			grantedScope: '["openid"]',
			approvedAtMs: String(NOW),
		});
		const polled = await store.poll(seed.deviceCode, NOW + 10_000);
		expect(polled.status).toBe("approved");
		if (polled.status === "approved") {
			expect(polled.authorization).toHaveProperty("amr", undefined);
			expect(polled.authorization).toHaveProperty("authTimeMs", undefined);
			expect(polled.authorization.subject).toBe("user-1");
		}
	});

	it("round-trips an amr value holding a comma, a quote and non-ASCII text", async () => {
		const amr = ["a,b", 'say "hi"', "認証", "\\u0000-not-an-escape", "[]"];
		const store = storeAt(freshPrefix());
		await store.create(seed);
		await store.approve({ userCode: seed.userCode, subject: "user-1", nowMs: NOW, amr });
		const polled = await store.poll(seed.deviceCode, NOW + 10_000);
		expect(polled.status === "approved" && polled.authorization.amr).toEqual(amr);
	});

	it.each([
		["not JSON", "pwd,mfa"],
		["an empty list", "[]"],
		["a list holding an empty string", '["pwd",""]'],
		["a list holding a number", '["pwd",1]'],
		["a JSON string", '"pwd"'],
		["a JSON object", '{"0":"pwd"}'],
	])("reads a stored amr that is %s as absent, never as part of one", async (_label, value) => {
		// Only an approval writes the field, and only a well-formed list; any
		// other value was written around the store, and reads as "cannot tell".
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		await store.create(seed);
		await store.approve({ userCode: seed.userCode, subject: "user-1", nowMs: NOW, amr: ["pwd"] });
		await raw.hset(keysAt(prefix).codeKey, "amr", value);
		const polled = await store.poll(seed.deviceCode, NOW + 10_000);
		expect(polled.status).toBe("approved");
		if (polled.status === "approved") expect(polled.authorization).toHaveProperty("amr", undefined);
	});

	it.each([
		["not a number", "soon"],
		["empty", ""],
		["blank", " "],
		["negative", "-1"],
		["fractional", "1.5"],
		["in exponent form", "1e3"],
		["past the Date range", "8640000000000001"],
	])("reads a stored authentication time that is %s as absent", async (_label, value) => {
		// Only an approval writes the field, as the whole epoch milliseconds of a
		// valid Date at or after the epoch; anything else reads as "cannot tell",
		// never as an instant of its own (an empty string is not epoch zero).
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		await store.create(seed);
		await store.approve({
			userCode: seed.userCode,
			subject: "user-1",
			nowMs: NOW,
			authTime: new Date(NOW - 60_000),
		});
		await raw.hset(keysAt(prefix).codeKey, "authTimeMs", value);
		const polled = await store.poll(seed.deviceCode, NOW + 10_000);
		expect(polled.status).toBe("approved");
		if (polled.status === "approved") {
			expect(polled.authorization).toHaveProperty("authTimeMs", undefined);
		}
	});
});

/**
 * What this adapter does with an untyped caller's falsy `requestedScope`: it
 * reads as a scopeless request, as in both bundled stores, which test the
 * field for truthiness. It is outside the port's types, so it is this
 * adapter's behaviour and not the contract's; a third-party store owes
 * nothing for it.
 */
describe("redis DeviceCodeStore — an untyped caller's falsy requestedScope", () => {
	it.each([
		["null", null],
		["an empty string", ""],
		["false", false],
		["zero", 0],
	])("reads %s as no scope, and still approves", async (_label, value) => {
		// Tested any other way, the store would write the value's JSON, read it
		// back as `[]`, and fail the approval script on it.
		const store = storeAt(freshPrefix());
		await store.create({ ...seed, requestedScope: value as unknown as undefined });
		expect((await store.findPendingByUserCode(seed.userCode, NOW))?.requestedScope).toBeUndefined();
		const decided = await store.approve({ userCode: seed.userCode, subject: "user-1", nowMs: NOW });
		expect(decided.status).toBe("ok");
		if (decided.status === "ok") expect(decided.authorization.grantedScope).toEqual([]);
	});
});
