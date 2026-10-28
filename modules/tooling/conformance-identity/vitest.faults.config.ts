import { faultRunReporter } from "@mod/conformance/testing";
import { evidenceReporter } from "@mod/spec-checklist/testing";
import { defineConfig } from "vitest/config";

export default defineConfig({
	test: {
		// The fault scenes alone, each on a Redis topology and a deployment of its own.
		include: ["test/**/*.faults.case.ts", "src/**/test/**/*.faults.case.ts"],
		reporters: ["default", evidenceReporter(), faultRunReporter()],
		testTimeout: 300_000,
		hookTimeout: 300_000,
		fileParallelism: false,
	},
});
