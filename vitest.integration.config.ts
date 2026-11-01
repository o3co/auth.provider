import { defineConfig } from "vitest/config";
import { evidenceReporter } from "./modules/tooling/spec-checklist/src/testing.ts";

export default defineConfig({
	test: {
		// The run's results, for the compliance of a CI run (spec-checklist's evidence).
		reporters: ["default", evidenceReporter()],
		// Follows the guard's integration-test convention; a missing outside system fails, not skips.
		include: [
			"modules/*/*/test/**/*.integration.test.ts",
			"modules/*/*/src/**/test/**/*.integration.test.ts",
		],
		testTimeout: 60_000,
		hookTimeout: 120_000,
	},
});
