import { defineConfig } from "vitest/config";
import { WORKSPACE_TEST_TIMEOUTS } from "../vitest.shared.mts";

export default defineConfig({
	test: {
		// #357: the workspace-wide deadline floor — rationale in vitest.shared.mts.
		...WORKSPACE_TEST_TIMEOUTS,
		include: ["src/**/__tests__/**/*.test.mts"],
		// #556: the test files in this package share one directory on disk and
		// must not run at the same time. `published-package.test.mts` runs
		// `npm pack`, whose `prepack` hook (`scripts/copy-templates.mjs`) deletes
		// `create-app/templates/standalone` and copies it back; every `scaffold()`
		// in `index.test.mts` copies FROM that directory. With files in parallel,
		// a scaffold that lands inside the delete-and-copy window reads a
		// half-written template and fails with ENOENT — which is how
		// `develop` CI run 34616122593 failed two `main()` tests while the pack
		// was in flight. Running the files one after the other costs the e2e
		// file's few seconds; it is the only ordering in which neither file can
		// observe the other.
		fileParallelism: false,
	},
});
