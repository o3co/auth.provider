import { defineConfig } from "vitest/config";

export default defineConfig({
	test: {
		include: ["src/**/__tests__/**/*.test.mts"],
		// #357: the workspace-wide deadline floor, repeated as literals rather
		// than imported from vitest.shared.mts — this template is copied
		// verbatim into scaffolded projects, where that file does not exist.
		// Rationale lives there: under a loaded parallel run, transform+import
		// alone can exceed vitest's 5s default, and a real hang still fails at
		// 20s.
		testTimeout: 20_000,
		hookTimeout: 20_000,
	},
});
