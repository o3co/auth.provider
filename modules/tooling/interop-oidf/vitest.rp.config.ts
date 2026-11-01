import { evidenceReporter } from "@mod/spec-checklist/testing";
import { defineConfig } from "vitest/config";

// The relying party plans meet a pattern of their own, one logging browsers in through an upstream.
export default defineConfig({
	test: {
		include: ["runs/rp.test.ts"],
		reporters: ["default", evidenceReporter()],
		fileParallelism: false,
		testTimeout: 30_000,
		hookTimeout: 120_000,
		env: { CONFORMANCE_PATTERN: "sso-federated" },
	},
});
