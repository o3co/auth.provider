import { defineConfig } from "vitest/config";
import { WORKSPACE_TEST_SETUP, WORKSPACE_TEST_TIMEOUTS } from "../../vitest.shared.mts";

export default defineConfig({
	test: {
		// #357: the workspace-wide deadline floor — rationale in vitest.shared.mts.
		...WORKSPACE_TEST_TIMEOUTS,
		// #556: supertest's server binds the loopback address it dials — see vitest.shared.mts.
		...WORKSPACE_TEST_SETUP,
		include: ["src/**/__tests__/**/*.test.mts"],
		// #626: a `@ts-expect-error` or `satisfies` assertion in a test only fires
		// under typecheck mode; a passing `vitest run` alone proves nothing about
		// it. The whole test tree is checked. Paired with tsconfig.test.json, and
		// both lists are needed, as core's config explains.
		typecheck: {
			enabled: true,
			include: ["src/**/__tests__/**/*.test.mts"],
			tsconfig: "./tsconfig.test.json",
		},
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
