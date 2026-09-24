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
 * run. Any other failure is reported as it is. Every failed attempt's
 * container is removed before anything else happens (see
 * `startDiscardingFailures`). In watch mode each rerun starts from empty
 * databases (`resetSharedRedis`). With no container runtime at
 * all the run still goes ahead: the files that do not touch Redis pass, and
 * each one that does fails in its `beforeAll` with the reason.
 */
import { randomUUID } from "node:crypto";
import { Redis } from "ioredis";
import {
	GenericContainer,
	getContainerRuntimeClient,
	type StartedTestContainer,
	Wait,
} from "testcontainers";
import type { TestProject } from "vitest/node";
import type { SharedRedis } from "./shared-redis.mjs";

/** Logical databases on the shared server: one per test file, with room to spare. */
const DATABASES = 128;

const START_ATTEMPTS = 3;
const PORTS_NOT_BOUND = /while waiting for container ports to be bound/;

/** The label each start attempt's container carries, so a failed one can be found and removed. */
const ATTEMPT_LABEL = "o3co.auth-provider.test-redis.attempt";

/**
 * Runs `attempt` with a fresh label until it starts a container, retrying only
 * Testcontainers' port-binding timeout, at most `attempts` times.
 *
 * After **any** failed attempt the container it labelled is discarded first.
 * Testcontainers 12 throws that timeout after it has created and started the
 * container and keeps no handle to it, so without this each retry left one
 * running — for good when Ryuk, the reaper, is disabled.
 */
export async function startDiscardingFailures(
	attempt: (label: string) => Promise<StartedTestContainer>,
	discard: (label: string) => Promise<void>,
	attempts = START_ATTEMPTS,
): Promise<StartedTestContainer> {
	for (let n = 1; ; n += 1) {
		const label = randomUUID();
		try {
			return await attempt(label);
		} catch (err) {
			await discard(label).catch((cleanup: unknown) => {
				console.warn(
					`test Redis: could not remove the container of a failed start (${ATTEMPT_LABEL}=${label}): ${String(cleanup)}`,
				);
			});
			if (n < attempts && err instanceof Error && PORTS_NOT_BOUND.test(err.message)) continue;
			throw err;
		}
	}
}

const startOnce = (label: string): Promise<StartedTestContainer> =>
	new GenericContainer("redis:7.2-alpine")
		.withCommand(["redis-server", "--databases", String(DATABASES)])
		.withExposedPorts(6379)
		.withLabels({ [ATTEMPT_LABEL]: label })
		// The server's own word that it is serving, rather than a probe run
		// inside the container: one fewer `docker exec` on a loaded daemon.
		.withWaitStrategy(Wait.forLogMessage(/Ready to accept connections/))
		.withStartupTimeout(120_000)
		.start();

/** Force-removes every container, running or not, that carries this attempt's label. */
const discardAttempt = async (label: string): Promise<void> => {
	const { container } = await getContainerRuntimeClient();
	const found = await container.dockerode.listContainers({
		all: true,
		filters: { label: [`${ATTEMPT_LABEL}=${label}`] },
	});
	await Promise.all(
		found.map((info) => container.dockerode.getContainer(info.Id).remove({ force: true, v: true })),
	);
};

/**
 * Empties every database on the shared server, the file counter in database
 * 0 included, so the next run hands out databases from 1 again.
 *
 * Watch mode reruns files against the same container, and each rerun takes
 * fresh databases: without this, 29 files ran the server's 127 test
 * databases out within a handful of reruns.
 */
export const resetSharedRedis = async (at: { host: string; port: number }): Promise<void> => {
	const io = new Redis({ host: at.host, port: at.port, db: 0 });
	try {
		await io.flushall();
	} finally {
		io.disconnect();
	}
};

export default async function setup(project: TestProject): Promise<() => Promise<void>> {
	let container: StartedTestContainer | undefined;
	let shared: SharedRedis;
	try {
		container = await startDiscardingFailures(startOnce, discardAttempt);
		shared = {
			host: container.getHost(),
			port: container.getMappedPort(6379),
			databases: DATABASES,
		};
	} catch (err) {
		shared = { unavailable: err instanceof Error ? err.message : String(err) };
	}
	project.provide("sharedRedis", shared);
	if ("host" in shared) {
		const at = shared;
		project.onTestsRerun(async () => {
			await resetSharedRedis(at);
		});
	}
	return async () => {
		await container?.stop();
	};
}
