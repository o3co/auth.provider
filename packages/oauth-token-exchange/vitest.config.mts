import { defineConfig } from "vitest/config";

export default defineConfig({
	test: {
		include: ["src/**/__tests__/**/*.test.mts"],
		typecheck: {
			enabled: true,
			include: [
				// CC-5 readonly compile-time contract tests. The @ts-expect-error
				// directives in this file only fire under typecheck mode.
				"src/__tests__/readonly-types.test.mts",
			],
			tsconfig: "./tsconfig.test.json",
		},
	},
});
