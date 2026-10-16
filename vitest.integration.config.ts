import { defineConfig } from "vitest/config";

export default defineConfig({
	test: {
		// Follows the guard's integration-test convention; a missing outside system fails, not skips.
		include: [
			"modules/*/*/test/**/*.integration.test.ts",
			"modules/*/*/src/**/test/**/*.integration.test.ts",
		],
		testTimeout: 60_000,
		hookTimeout: 120_000,
	},
});
