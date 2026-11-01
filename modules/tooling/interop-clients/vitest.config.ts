import { evidenceReporter } from "@mod/spec-checklist/testing";
import { defineConfig } from "vitest/config";

export default defineConfig({
	test: {
		reporters: ["default", evidenceReporter()],
		testTimeout: 120_000,
		hookTimeout: 300_000,
		fileParallelism: false,
		// Each file meets a pattern's app: the full template with every feature that opts in, and the
		// services' (`a2a`). The reporter, in the main process, sees no pattern: the run is the library's.
		projects: [
			{
				extends: true,
				test: {
					name: "full",
					include: ["test/flows.case.ts"],
					env: { CONFORMANCE_PATTERN: "full+opt-ins" },
				},
			},
			{
				extends: true,
				test: {
					name: "services",
					include: ["test/services.case.ts"],
					env: { CONFORMANCE_PATTERN: "a2a" },
				},
			},
		],
	},
});
