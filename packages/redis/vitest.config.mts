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
		},
	},
});
