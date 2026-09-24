/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
import Redis from "ioredis";
import { GenericContainer, type StartedTestContainer } from "testcontainers";
import { afterAll, beforeAll } from "vitest";
import type { RefreshTokenFamilyClient } from "#/clients.mjs";
import { makeIoredisClients } from "#/ioredis.mjs";
import { createRedisRefreshTokenFamilyStore } from "#/refresh-token-family.mjs";
import { runRefreshTokenFamilyStoreContract } from "./adapters.refresh-token-family.contract.mjs";
import { runRefreshTokenFamilyClientDuplicateContract } from "./adapters.refresh-token-family-client.contract.mjs";

let container: StartedTestContainer;
let client: Redis;
let keyCounter = 0;

/**
 * The client a deployment runs: `makeIoredisClients`'s, not one written for
 * this file. The hand-rolled adapter this replaced resolved `exec()` with
 * ioredis's per-command error tuples, so a `SET` Redis refused inside the
 * `MULTI` — a fractional or NaN `PX` — read as a committed rotation while the
 * family stayed as it was. `RefreshTokenFamilyMultiClient.exec` forbids that,
 * and the shipped client keeps it.
 */
const real = (raw: Redis): RefreshTokenFamilyClient =>
	makeIoredisClients(raw).refreshTokenFamilyClient;

beforeAll(async () => {
	container = await new GenericContainer("redis:7.2-alpine")
		.withExposedPorts(6379)
		.withStartupTimeout(60_000)
		.start();
	client = new Redis({
		host: container.getHost(),
		port: container.getMappedPort(6379),
	});
}, 90_000);

afterAll(async () => {
	await client?.quit();
	await container?.stop();
});

runRefreshTokenFamilyStoreContract(async () => {
	keyCounter++;
	return createRedisRefreshTokenFamilyStore({
		client: real(client),
		keyPrefix: `rtfam:test-${keyCounter}:`,
		casRetryLimit: 50, // generous limit for the concurrency property test
	});
});

// T4 hardening (Claude review I1): RefreshTokenFamilyClient.duplicate() NORMATIVE contract
// suite, against the shipped client, so a refactor of `makeIoredisClients`
// keeps the WATCH-isolation guarantee A3 updateFamily depends on.
runRefreshTokenFamilyClientDuplicateContract(() => real(client), `rtfam-contract-${++keyCounter}:`);
