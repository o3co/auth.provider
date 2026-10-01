import { defineConfig } from "vitest/config";
import { WORKSPACE_TEST_TIMEOUTS } from "../vitest.shared.mts";

export default defineConfig({
	test: {
		// The workspace-wide deadline floor; rationale in vitest.shared.mts.
		...WORKSPACE_TEST_TIMEOUTS,
		include: ["src/**/__tests__/**/*.test.mts"],
		// The test files share one directory on disk and must not run in
		// parallel: `published-package.test.mts` runs `npm pack`, whose `prepack`
		// hook (`scripts/copy-templates.mjs`) deletes and recopies
		// `create-app/templates`, and every `scaffold()` in `index.test.mts`
		// copies from it. A scaffold inside that window fails with ENOENT.
		fileParallelism: false,
		// A `@ts-expect-error` or `satisfies` in a test fires only under
		// typecheck; tsconfig.test.json is the program it compiles.
		typecheck: {
			enabled: true,
			include: ["src/**/__tests__/**/*.test.mts"],
			tsconfig: "./tsconfig.test.json",
		},
	},
});
