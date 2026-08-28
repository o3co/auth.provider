import { defineConfig } from "vitest/config";
import { WORKSPACE_TEST_TIMEOUTS } from "../../vitest.shared.mts";

export default defineConfig({
	test: {
		// #357: the workspace-wide deadline floor — rationale in vitest.shared.mts.
		...WORKSPACE_TEST_TIMEOUTS,
		include: ["src/**/__tests__/**/*.test.mts"],
		typecheck: {
			enabled: true,
			include: [
				// CC-5 readonly compile-time contract tests. The @ts-expect-error
				// directives in this file only fire under typecheck mode.
				"src/__tests__/readonly-types.test.mts",
			],
			tsconfig: "./tsconfig.test.json",
		},
	},
});
