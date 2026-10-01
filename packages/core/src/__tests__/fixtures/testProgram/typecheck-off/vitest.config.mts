import { defineConfig } from "vitest/config";

export default defineConfig({
	test: {
		include: ["src/**/*.probe.mts"],
		typecheck: {
			enabled: false,
			include: ["src/**/*.probe.mts"],
			tsconfig: "./tsconfig.test.json",
		},
	},
});
