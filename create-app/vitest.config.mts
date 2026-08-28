import { defineConfig } from "vitest/config";
import { WORKSPACE_TEST_TIMEOUTS } from "../vitest.shared.mts";

export default defineConfig({
	test: {
		// #357: the workspace-wide deadline floor — rationale in vitest.shared.mts.
		...WORKSPACE_TEST_TIMEOUTS,
		include: ["src/**/__tests__/**/*.test.mts"],
	},
});
