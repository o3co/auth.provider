import { defineConfig } from "vitest/config";

export default defineConfig({
	test: {
		// Follows the guard's test-file convention.
		include: ["test/**/*.case.ts"],
		testTimeout: 60_000,
		hookTimeout: 120_000,
		fileParallelism: false,
	},
});
