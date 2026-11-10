import { evidenceReporter } from "@mod/spec-checklist/testing";
import { defineConfig } from "vitest/config";

export default defineConfig({
	test: {
		// The area's set-ups register as its package's entry loads.
		setupFiles: ["./src/main.ts"],
		// Follows the guard's test-file convention.
		include: ["test/**/*.case.ts"],
		reporters: ["default", evidenceReporter()],
		testTimeout: 60_000,
		hookTimeout: 120_000,
		fileParallelism: false,
	},
});
