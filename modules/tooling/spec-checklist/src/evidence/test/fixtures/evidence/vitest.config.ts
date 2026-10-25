import { defineConfig } from "vitest/config";
import { evidenceReporter } from "../../../reporter.ts";

export default defineConfig({
	root: import.meta.dirname,
	test: { include: ["*.sample.ts"], reporters: ["default", evidenceReporter()] },
});
