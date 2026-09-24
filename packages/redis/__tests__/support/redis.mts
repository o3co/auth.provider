/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

/**
 * A test file's Redis: its own logical database on the one container the run
 * shares (`redis-container.global.mts`), and the server's clock.
 */
import { Redis } from "ioredis";
import { inject } from "vitest";
import type { SharedRedis } from "./shared-redis.mjs";

/** Where this file's database is: pass it to `new Redis(…)`, as many connections as the file needs. */
export interface TestRedis {
	readonly host: string;
	readonly port: number;
	readonly db: number;
}

/** Database 0 holds only this counter; files get 1, 2, 3, … in the order they ask. */
const NEXT_DATABASE = "test-support:next-database";

/**
 * Takes a database no other file of this run uses. Call it once per file, in
 * `beforeAll`, and open every connection the file needs from the one answer.
 *
 * Handed out by `INCR` on the server itself, because files run in separate
 * workers and nothing else is shared between them: the counter is the one
 * place that sees every file ask.
 */
export async function testRedis(): Promise<TestRedis> {
	const shared: SharedRedis = inject("sharedRedis");
	if ("unavailable" in shared) {
		throw new Error(`the shared Redis container did not start: ${shared.unavailable}`);
	}
	const { host, port, databases } = shared;
	const counter = new Redis({ host, port, db: 0 });
	try {
		const db = await counter.incr(NEXT_DATABASE);
		if (db >= databases) {
			throw new Error(
				`every one of the shared Redis's ${databases - 1} test databases is taken; raise DATABASES in redis-container.global.mts`,
			);
		}
		return { host, port, db };
	} finally {
		counter.disconnect();
	}
}

/**
 * The server's clock, in epoch milliseconds — what a key's `PX`/`PEXPIREAT`
 * and the scripts' `TIME` are judged on. A container's clock can sit tens of
 * milliseconds, or more on a loaded machine, either side of the host's, so a
 * test that waits for something to expire in Redis waits on this one.
 *
 * Takes the connection lazily: a contract suite is handed its clock while the
 * file is collected, before `beforeAll` has opened the connection.
 */
export const serverClock = (connection: () => Redis) => async (): Promise<number> => {
	const [seconds, microseconds] = await connection().time();
	return Number(seconds) * 1000 + Math.floor(Number(microseconds) / 1000);
};
