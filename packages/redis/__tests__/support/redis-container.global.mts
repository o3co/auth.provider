/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

/**
 * One Redis container for the whole test run of this package, where every
 * file used to start its own.
 *
 * Every Redis-backed file booted `redis:7.2-alpine` in its own `beforeAll`,
 * and on a loaded machine — a whole-workspace run, several runs at once — one
 * of them sooner or later failed before its first test with "Timed out after
 * 10000ms while waiting for container ports to be bound to the host". That
 * wait is Testcontainers' own and fixed at ten seconds (its
 * `inspectContainerUntilPortsExposed`); `withStartupTimeout` does not reach
 * it, so no per-file timeout could be raised to cover it. What can be changed
 * is how often it is paid: once per run, before any test file starts, instead
 * of once per file while other files are already running.
 *
 * Files stay isolated by database, not by container: each takes a logical
 * database of its own (`testRedis()` in `redis.mts`), so the key prefixes
 * files happen to share, and anything a file counts or scans, stay its own.
 *
 * The one start left is retried when — and only when — it fails that port
 * wait: Docker publishing a port late is the machine's state, not this
 * suite's, and a second attempt costs seconds where a failed run costs the
 * run. Any other failure is reported as it is. With no container runtime at
 * all the run still goes ahead: the files that do not touch Redis pass, and
 * each one that does fails in its `beforeAll` with the reason.
 */
import { GenericContainer, type StartedTestContainer, Wait } from "testcontainers";
import type { TestProject } from "vitest/node";
import type { SharedRedis } from "./shared-redis.mjs";

/** Logical databases on the shared server: one per test file, with room to spare. */
const DATABASES = 128;

const START_ATTEMPTS = 3;
const PORTS_NOT_BOUND = /while waiting for container ports to be bound/;

const start = async (attempt = 1): Promise<StartedTestContainer> => {
	try {
		return await new GenericContainer("redis:7.2-alpine")
			.withCommand(["redis-server", "--databases", String(DATABASES)])
			.withExposedPorts(6379)
			// The server's own word that it is serving, rather than a probe run
			// inside the container: one fewer `docker exec` on a loaded daemon.
			.withWaitStrategy(Wait.forLogMessage(/Ready to accept connections/))
			.withStartupTimeout(120_000)
			.start();
	} catch (err) {
		if (attempt < START_ATTEMPTS && err instanceof Error && PORTS_NOT_BOUND.test(err.message)) {
			return start(attempt + 1);
		}
		throw err;
	}
};

export default async function setup(project: TestProject): Promise<() => Promise<void>> {
	let container: StartedTestContainer | undefined;
	let shared: SharedRedis;
	try {
		container = await start();
		shared = {
			host: container.getHost(),
			port: container.getMappedPort(6379),
			databases: DATABASES,
		};
	} catch (err) {
		shared = { unavailable: err instanceof Error ? err.message : String(err) };
	}
	project.provide("sharedRedis", shared);
	return async () => {
		await container?.stop();
	};
}
