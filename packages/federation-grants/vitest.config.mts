import { defineConfig } from "vitest/config";
import { WORKSPACE_TEST_SETUP, WORKSPACE_TEST_TIMEOUTS } from "../../vitest.shared.mts";

export default defineConfig({
	test: {
		// #357: the workspace-wide deadline floor — rationale in vitest.shared.mts.
		...WORKSPACE_TEST_TIMEOUTS,
		// #556: supertest's server binds the loopback address it dials — see vitest.shared.mts.
		...WORKSPACE_TEST_SETUP,
		include: ["src/**/__tests__/**/*.test.mts"],
		// As every sibling package declares it. Without it the test helpers under
		// `__tests__/` (the harness, the acquisition fixture) were counted as
		// source, and their unexercised stubs as untested lines.
		coverage: {
			provider: "v8",
			reporter: ["text", "json", "json-summary"],
			reportsDirectory: "./coverage",
			include: ["src/**/*.mts"],
			exclude: ["src/**/__tests__/**", "src/**/*.d.mts", "dist/**"],
			all: true,
		},
	},
});
