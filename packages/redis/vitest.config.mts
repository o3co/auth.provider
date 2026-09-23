/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
import { defineConfig } from "vitest/config";
import { WORKSPACE_TEST_SETUP, WORKSPACE_TEST_TIMEOUTS } from "../../vitest.shared.mts";

export default defineConfig({
	test: {
		...WORKSPACE_TEST_TIMEOUTS,
		// #556: supertest's server binds the loopback address it dials — see vitest.shared.mts.
		...WORKSPACE_TEST_SETUP,
		// Raises the #357 workspace floor (never lowers it): testcontainers
		// boot + Redis warm-up takes time on first run.
		testTimeout: 30_000,
		hookTimeout: 30_000,
		typecheck: {
			enabled: true,
			// tsconfig.test.json, not the build config: the build config holds
			// `src` alone, and a test file outside tsc's program is never
			// compiled — its assertions pass without being checked (#626).
			tsconfig: "./tsconfig.test.json",
			// Type-level assertions in __tests__/types.test.mts (per-purpose
			// client shapes + ComponentMap declaration-merge invariants) must
			// run through tsc rather than be silently treated as runtime no-ops.
			// `typecheck.include` REPLACES vitest's default pattern entirely, so
			// re-include the default `*.test-d.*` glob in addition to the
			// runtime+typecheck hybrid file.
			// `code-repository.test.mts` and `device-code-store.test.mts` (#626):
			// their fixtures — and the contract the latter runs — build `Code` and
			// `DeviceAuthorization` inputs, which name every key; uncompiled,
			// nothing would hold them to it.
			include: [
				"**/*.test-d.?(c|m)[jt]s?(x)",
				"__tests__/types.test.mts",
				"__tests__/code-repository.test.mts",
				"__tests__/device-code-store.test.mts",
				// #626: the intent store's tests build intents, which name every key;
				// the contract copy is compiled through the file that runs it.
				"__tests__/federation-grant-intent-store-codec.test.mts",
				"__tests__/federation-grant-intent-store.integration.test.mts",
				// #626: the federation grant store's tests build grants,
				// authorizations, credentials and failure stamps, which name every
				// key. `federation-grant-store.integration.test.mts` and the
				// contract copy it runs are in tsconfig.test.json only: the file
				// declares no suite of its own, which vitest 5's typecheck pass
				// reports as "No test suite found" — and an error in a file in the
				// program but not collected still fails the run.
				"__tests__/federation-grant-store.order.test.mts",
				"__tests__/federation-grant-store.faults.integration.test.mts",
				"__tests__/federation-grant-primitives.integration.test.mts",
				"__tests__/internal/federation-grant-codec.test.mts",
				// #626: the session contract's parity test. The contract and the file
				// that runs it are in tsconfig.test.json only: that file declares no
				// suite of its own, which vitest 5 reports as "No test suite found".
				"__tests__/user-session-contract-parity.test.mts",
			],
		},
	},
});
