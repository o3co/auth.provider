/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

/**
 * Redis-backed `DeviceCodeStore` (#433) against the shared conformance suite,
 * on a real Redis.
 *
 * The suite's "two polls racing for the same approval" case is the one that
 * needs the real server: it is the difference between atomicity that comes
 * from a Lua script and atomicity that comes from a round trip, and a fake
 * that answers from a `Map` cannot tell the two apart. The cases below the
 * suite pin what is Redis-specific — the key layout the Cluster argument
 * rests on, the TTL, and that `expired` is answered from the timestamp.
 */

import Redis from "ioredis";
import { GenericContainer, type StartedTestContainer } from "testcontainers";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createRedisDeviceCodeStore } from "#/device-code-store.mjs";
import { makeIoredisClients } from "#/ioredis.mjs";
import { runDeviceCodeStoreContract } from "./adapters.device-code-store.contract.mjs";

let container: StartedTestContainer;
let raw: Redis;
let keyCounter = 0;

beforeAll(async () => {
	container = await new GenericContainer("redis:7.2-alpine")
		.withExposedPorts(6379)
		.withStartupTimeout(60_000)
		.start();
	raw = new Redis({ host: container.getHost(), port: container.getMappedPort(6379) });
}, 90_000);

afterAll(async () => {
	await raw?.quit();
	await container?.stop();
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

describe("createRedisDeviceCodeStore — what is Redis-specific (#433)", () => {
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
		// The memory adapter's semantics for the optional field: absent stays
		// absent on the way out, and an approval of a scopeless request grants
		// the empty set rather than failing or inventing one.
		const store = storeAt(freshPrefix());
		const { requestedScope: _omitted, ...scopeless } = seed;
		await store.create(scopeless);

		const found = await store.findPendingByUserCode(seed.userCode, NOW);
		expect(found).not.toBeNull();
		expect(found).not.toHaveProperty("requestedScope");

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
