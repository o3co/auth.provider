/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
import { defineConfig } from "vitest/config";

export default defineConfig({
	test: {
		// testcontainers boot + Redis warm-up takes time on first run.
		testTimeout: 30_000,
		hookTimeout: 30_000,
		typecheck: {
			enabled: true,
			tsconfig: "./tsconfig.json",
			// Type-level assertions in __tests__/types.test.mts (per-purpose
			// client shapes + ComponentMap declaration-merge invariants) must
			// run through tsc rather than be silently treated as runtime no-ops.
			// `typecheck.include` REPLACES vitest's default pattern entirely, so
			// re-include the default `*.test-d.*` glob in addition to the
			// runtime+typecheck hybrid file.
			include: ["**/*.test-d.?(c|m)[jt]s?(x)", "__tests__/types.test.mts"],
		},
	},
});
