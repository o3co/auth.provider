import { evidenceReporter } from "@mod/spec-checklist/testing";
import { configDefaults, defineConfig } from "vitest/config";

export default defineConfig({
	test: {
		// The area's set-ups register as its package's entry loads.
		setupFiles: ["./src/main.ts"],
		// Follows the guard's test-file convention; the fault scenes run in their own run.
		include: ["test/**/*.case.ts"],
		exclude: [...configDefaults.exclude, "**/*.faults.case.ts"],
		reporters: ["default", evidenceReporter()],
		testTimeout: 60_000,
		hookTimeout: 120_000,
		fileParallelism: false,
	},
});
