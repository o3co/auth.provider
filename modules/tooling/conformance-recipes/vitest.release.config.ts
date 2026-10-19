import { defineConfig } from "vitest/config";

export default defineConfig({
	test: {
		// Recipes built against the packed release, which only the release check makes.
		include: ["test/**/*.release.ts"],
		testTimeout: 600_000,
		hookTimeout: 120_000,
	},
});
