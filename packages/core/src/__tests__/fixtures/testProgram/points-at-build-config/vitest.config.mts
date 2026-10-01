import { defineConfig } from "vitest/config";

export default defineConfig({
	test: {
		include: ["src/**/*.probe.mts"],
		typecheck: {
			enabled: true,
			include: ["src/**/*.probe.mts"],
			tsconfig: "./tsconfig.json",
		},
	},
});
