import { defineConfig } from "vitest/config";
import { WORKSPACE_TEST_TIMEOUTS } from "../../vitest.shared.mts";

export default defineConfig({
	test: {
		...WORKSPACE_TEST_TIMEOUTS,
		include: ["src/**/__tests__/**/*.test.mts"],
	},
});
