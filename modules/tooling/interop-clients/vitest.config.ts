import { evidenceReporter } from "@mod/spec-checklist/testing";
import { defineConfig } from "vitest/config";

export default defineConfig({
	test: {
		// Follows the guard's test-file convention.
		include: ["test/**/*.case.ts"],
		reporters: ["default", evidenceReporter()],
		// The libraries meet the full template with every feature that opts in; the reporter, in the main
		// process, does not see it, so the run is named by its library alone.
		env: { CONFORMANCE_PATTERN: "full+opt-ins" },
		testTimeout: 120_000,
		hookTimeout: 300_000,
		fileParallelism: false,
	},
});
