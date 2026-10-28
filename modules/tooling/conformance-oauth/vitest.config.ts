import { evidenceReporter } from "@mod/spec-checklist/testing";
import { configDefaults, defineConfig } from "vitest/config";

export default defineConfig({
	test: {
		// Follows the guard's test-file convention; the fault scenes run in their own run.
		include: ["test/**/*.case.ts", "src/**/test/*.case.ts"],
		exclude: [...configDefaults.exclude, "**/*.faults.case.ts"],
		reporters: ["default", evidenceReporter()],
		testTimeout: 60_000,
		hookTimeout: 120_000,
		fileParallelism: false,
	},
});
