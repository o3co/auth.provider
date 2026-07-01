/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
import Redis from "ioredis";
import { GenericContainer, type StartedTestContainer } from "testcontainers";
import { afterAll, beforeAll } from "vitest";
import type {
	DisposableRefreshTokenFamilyClient,
	RefreshTokenFamilyClient,
	RefreshTokenFamilyMultiClient,
} from "../src/clients.mjs";
import { createRedisRefreshTokenFamilyStore } from "../src/refresh-token-family.mjs";
import { runRefreshTokenFamilyStoreContract } from "./adapters.refresh-token-family.contract.mjs";
import { runRefreshTokenFamilyClientDuplicateContract } from "./adapters.refresh-token-family-client.contract.mjs";

let container: StartedTestContainer;
let client: Redis;
let keyCounter = 0;

/**
 * Adapt a raw ioredis Redis instance to the structural RefreshTokenFamilyClient +
 * provide `duplicate()` returning a DisposableRefreshTokenFamilyClient
 * (Symbol.asyncDispose calls the duplicated ioredis instance's quit()). The base
 * client itself is NOT disposable — only duplicates owned by `updateFamily` need
 * lifetime management.
 */
const adapt = (raw: Redis): RefreshTokenFamilyClient => {
	const buildMulti = (io: Redis): RefreshTokenFamilyMultiClient => {
		const m = io.multi();
		const facade: RefreshTokenFamilyMultiClient = {
			set: (key, value, _mode, ttlMs) => {
				m.set(key, value, "PX", ttlMs);
				return facade;
			},
			exec: async () => m.exec(),
		};
		return facade;
	};

	const buildClient = (io: Redis): RefreshTokenFamilyClient => ({
		set: (key, value, _mode, ttlMs, _condition) =>
			io.set(key, value, "PX", ttlMs, "NX") as Promise<"OK" | null>,
		get: (key) => io.get(key),
		pttl: (key) => io.pttl(key),
		watch: (...keys) => io.watch(...keys) as Promise<"OK">,
		unwatch: () => io.unwatch() as Promise<"OK">,
		multi: () => buildMulti(io),
		duplicate: (): DisposableRefreshTokenFamilyClient => {
			const dup = io.duplicate();
			const inner = buildClient(dup);
			return Object.assign(inner, {
				[Symbol.asyncDispose]: async () => {
					await dup.quit();
				},
			});
		},
	});

	return buildClient(raw);
};

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
		client: adapt(client),
		keyPrefix: `rtfam:test-${keyCounter}:`,
		casRetryLimit: 50, // generous limit for the concurrency property test
	});
});

// T4 hardening (Claude review I1): RefreshTokenFamilyClient.duplicate() NORMATIVE contract
// suite. The `adapt()` wrapper above is the canonical in-tree implementation;
// running the contract against it ensures any future refactor of `adapt()`
// (or any consumer's wrapper) preserves the WATCH-isolation guarantee that
// A3 updateFamily depends on.
runRefreshTokenFamilyClientDuplicateContract(
	() => adapt(client),
	`rtfam-contract-${++keyCounter}:`,
);
