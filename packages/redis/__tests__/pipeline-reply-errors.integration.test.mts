/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

/**
 * What a `MULTI`/`EXEC` whose queued command Redis refused throws, against a
 * real Redis: ioredis resolves `exec()` with the refusal inside the reply, and
 * the wrapper turns it into an error.
 *
 * That error says which operation failed in fixed words and carries the reply
 * error as `cause`. The reply's text is Redis's, about the command it
 * refused — and a refusal can quote the command's arguments — so it is never
 * copied into the message: the message goes wherever the store's caller puts
 * it, and `loggableError` projects the cause, cutting the quoted arguments.
 */

import { randomUUID } from "node:crypto";
import { loggableError } from "@o3co/auth-provider-core";
import { Redis } from "ioredis";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { makeIoredisClients } from "#/ioredis.mjs";
import { testRedis } from "./support/redis.mjs";

let raw: Redis;

beforeAll(async () => {
	raw = new Redis(await testRedis());
});

afterAll(async () => {
	raw?.disconnect();
});

/** What `run` rejects with. */
const failureOf = async (run: () => Promise<unknown>): Promise<Error & { cause: Error }> => {
	try {
		await run();
	} catch (err) {
		return err as Error & { cause: Error };
	}
	throw new Error("the pipeline was expected to fail");
};

describe("a queued command Redis refused inside MULTI/EXEC", () => {
	it("sAddWithTtl: the operation in fixed words, Redis's reply on the cause", async () => {
		const key = `pipeline-errors:set:${randomUUID()}`;
		// A string where the index set belongs: the SADD is refused at EXEC.
		await raw.set(key, "not-a-set");
		const { federationTokenStoreClient } = makeIoredisClients(raw);

		const err = await failureOf(() =>
			federationTokenStoreClient.sAddWithTtl(key, "member", 60_000),
		);

		expect(err).toBeInstanceOf(Error);
		expect(err.message).toBe(
			"federationTokenStoreClient.sAddWithTtl: a queued command failed inside MULTI/EXEC",
		);
		expect(err.cause).toBeInstanceOf(Error);
		expect(err.cause.message).toMatch(/^WRONGTYPE /);
		expect(err.message).not.toContain(err.cause.message);
		expect(loggableError(err)).toMatchObject({
			detail: "federationTokenStoreClient.sAddWithTtl: a queued command failed inside MULTI/EXEC",
			cause: { name: "ReplyError", detail: expect.stringMatching(/^WRONGTYPE /) },
		});
	});

	it("a purpose's multi().exec(): the same, named for that purpose", async () => {
		const key = `pipeline-errors:hash:${randomUUID()}`;
		await raw.set(key, "not-a-hash");
		const pipeline = makeIoredisClients(raw).sessionRPRegistryClient.multi();
		pipeline.hSet(key, "field", "value").pExpireGT(key, Date.now() + 60_000);

		const err = await failureOf(() => pipeline.exec());

		expect(err.message).toBe(
			"sessionRPRegistryClient.exec: a queued command failed inside MULTI/EXEC",
		);
		expect(err.cause.message).toMatch(/^WRONGTYPE /);
	});
});
