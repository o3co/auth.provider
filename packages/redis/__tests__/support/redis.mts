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

// --- Waiting for an expiry ----------------------------------------------------
//
// A fixed sleep after a short expiry is right only when the sleep and the
// expiry run on one clock and nothing else is running. Neither holds here: a
// Redis key expires on the server's clock, a relative `PX` starts when the
// command reaches the server rather than when the test sent it, and a loaded
// run reaches its next line late. So a sleep either read an entry the store had
// already dropped, or checked one it had not dropped yet. What these helpers
// wait for is the expiry itself — on the clock the store judges it by — and
// each gives up, loudly, at a deadline a correct store is well inside.

/** How long past an expiry a store may take to show it before a test calls it a defect. */
export const EXPIRY_GRACE_MS = 5_000;

const pause = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Polls `holds` until it does. Fails once the host clock is past
 * `notAfterMs` and it still does not: a bounded wait, never an open one.
 */
export async function until(
	holds: () => Promise<boolean>,
	what: string,
	notAfterMs: number,
): Promise<void> {
	for (;;) {
		if (await holds()) return;
		if (Date.now() > notAfterMs) {
			if (await holds()) return;
			throw new Error(`timed out waiting for ${what}`);
		}
		await pause(20);
	}
}

/**
 * The shape the contract suites take for a store's expiry (each suite declares
 * it as `ExpiryClock`): the clock the store expires entries by, and a wait
 * that resolves once the store has let everything expiring at `at` go.
 */
export interface ExpiryClock {
	now(): Promise<number>;
	passed(at: Date): Promise<void>;
}

/** Resolves once the server's clock, and the host's, are past `atMs`. */
export const serverPasses = (connection: () => Redis) => {
	const now = serverClock(connection);
	return (atMs: number): Promise<void> =>
		until(
			async () => Date.now() > atMs && (await now()) > atMs,
			`the server clock to pass ${new Date(atMs).toISOString()}`,
			atMs + EXPIRY_GRACE_MS,
		);
};

/**
 * For a store whose keys carry an absolute deadline — `PEXPIREAT`, `PXAT`, a
 * score compared with the server's `TIME`: the entry is gone once the server's
 * clock is past it.
 */
export const serverDeadlines = (connection: () => Redis): ExpiryClock => {
	const passes = serverPasses(connection);
	return {
		now: serverClock(connection),
		passed: (at) => passes(at.getTime()),
	};
};

/**
 * For a store whose keys carry a relative `PX`: the life runs from when the
 * command reached the server, which the test cannot see, so the wait is for
 * the keys themselves — every key under the store's prefix (`prefix()`, read
 * when the wait starts, as a contract's store is created per test) — to be
 * gone, and for the host to be past `at` as well.
 */
export const keysExpire = (connection: () => Redis, prefix: () => string): ExpiryClock => ({
	now: serverClock(connection),
	passed: (at) => {
		const pattern = `${prefix()}*`;
		return until(
			async () => Date.now() > at.getTime() && (await connection().keys(pattern)).length === 0,
			`every key under ${pattern} to expire`,
			at.getTime() + EXPIRY_GRACE_MS,
		);
	},
});

/**
 * An expiry a second ahead of whichever clock is later — the host's, which an
 * adapter checks a write against, and the server's, which expires it — so a
 * read that follows the write lands well inside it however loaded the run is.
 */
export const aheadOfServer = (connection: () => Redis) => {
	const now = serverClock(connection);
	return async (): Promise<Date> => new Date(Math.max(Date.now(), await now()) + 1_000);
};

/**
 * Runs `write`, and answers the latest server instant the key it wrote with a
 * relative `PX` can live to.
 *
 * That life starts when the command reaches the server, which the test cannot
 * see; it ends no later than the server's clock read after `write` returns
 * plus the longest `PX` the write can have sent. `lifeMs` is handed the host's
 * clock read before `write` started, so an adapter that sends
 * `expiresAtMs - Date.now()` is bounded by `(before) => expiresAtMs - before`.
 * Once the server is past the answer a correct adapter's key is gone, whatever
 * the load; before it, it may still be there.
 */
export async function relativeDeadline(
	connection: () => Redis,
	write: () => Promise<unknown>,
	lifeMs: (hostBeforeMs: number) => number,
): Promise<number> {
	const hostBefore = Date.now();
	await write();
	const serverAfter = await serverClock(connection)();
	return serverAfter + Math.ceil(lifeMs(hostBefore));
}
