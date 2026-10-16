import { defineConfig } from "vitest/config";

export default defineConfig({
	test: {
		// The patterns follow the workspace definition and the guard's test-file conventions (an
		// internal module keeps its tests in its own dir); tests that need an outside system run in the
		// integration config instead.
		include: ["modules/*/*/test/**/*.test.ts", "modules/*/*/src/**/test/**/*.test.ts"],
		exclude: ["**/*.integration.test.ts", "**/node_modules/**"],
	},
});
