import { evidenceReporter } from "@mod/spec-checklist/testing";
import { defineConfig } from "vitest/config";

// Each plan starts the suite on its fixed ports, so the files run one at a time; the root config
// never reads runs/, which needs Docker.
export default defineConfig({
	test: {
		include: ["runs/*.test.ts"],
		reporters: ["default", evidenceReporter()],
		fileParallelism: false,
		testTimeout: 30_000,
		hookTimeout: 120_000,
		env: { CONFORMANCE_PATTERN: "simple-web" },
	},
});
