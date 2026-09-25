/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
import { defineConfig } from "vitest/config";
import { WORKSPACE_TEST_SETUP, WORKSPACE_TEST_TIMEOUTS } from "../../vitest.shared.mts";

export default defineConfig({
	test: {
		...WORKSPACE_TEST_TIMEOUTS,
		// #556: supertest's server binds the loopback address it dials.
		...WORKSPACE_TEST_SETUP,
		// Raises the #357 floor, as packages/redis does: the Redis-backed file
		// boots against a real server on a loaded host.
		testTimeout: 30_000,
		hookTimeout: 30_000,
		include: ["src/**/__tests__/**/*.test.mts"],
		// The Redis package's one container for the run, each file on a
		// database of its own (`testRedis()`); see the file for why.
		globalSetup: ["../../packages/redis/__tests__/support/redis-container.global.mts"],
	},
});
