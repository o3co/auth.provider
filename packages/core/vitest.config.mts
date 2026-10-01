import { defineConfig } from "vitest/config";
import { WORKSPACE_TEST_SETUP, WORKSPACE_TEST_TIMEOUTS } from "../../vitest.shared.mts";

export default defineConfig({
	test: {
		// #357: the workspace-wide deadline floor — rationale in vitest.shared.mts.
		...WORKSPACE_TEST_TIMEOUTS,
		// #556: supertest's server binds the loopback address it dials — see vitest.shared.mts.
		...WORKSPACE_TEST_SETUP,
		include: ["src/**/__tests__/**/*.test.mts"],
		typecheck: {
			enabled: true,
			// Every test file, as the run collects them. vitest's typecheck reads
			// a file's suites from the file itself, so each declares one there.
			include: ["src/**/__tests__/**/*.test.mts"],
			// tsconfig.test.json, not the build config: the build config leaves
			// `__tests__` out. Its program takes every file under `src`, and an
			// error in any file of it fails the run.
			tsconfig: "./tsconfig.test.json",
		},
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
