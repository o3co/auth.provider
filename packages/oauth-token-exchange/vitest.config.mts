import { defineConfig } from "vitest/config";
import { WORKSPACE_TEST_SETUP, WORKSPACE_TEST_TIMEOUTS } from "../../vitest.shared.mts";

export default defineConfig({
	test: {
		// #357: the workspace-wide deadline floor — rationale in vitest.shared.mts.
		...WORKSPACE_TEST_TIMEOUTS,
		// #556: supertest's server binds the loopback address it dials — see vitest.shared.mts.
		...WORKSPACE_TEST_SETUP,
		include: ["src/**/__tests__/**/*.test.mts"],
		// #626: a `@ts-expect-error` or `satisfies` assertion in a test only fires
		// under typecheck mode; a passing `vitest run` alone proves nothing about
		// it. The whole test tree is checked. Paired with tsconfig.test.json, and
		// both lists are needed, as core's config explains.
		typecheck: {
			enabled: true,
			include: ["src/**/__tests__/**/*.test.mts"],
			// The two files below carried pre-existing type errors in the test
			// itself when the whole tree was switched on (51 in 2 files, of 9;
			// 5 more in 3 files were one-line fixture gaps, fixed). They are
			// named here rather than hidden behind a narrower glob, with the
			// count at exclusion and the cause, as oauth's config does. The same
			// list is the `exclude` of tsconfig.test.json, which has to keep
			// them out of tsc's program. TODO(#626): remove a file as its cause
			// is fixed. The cause:
			//
			//  [F] a stale fixture shape or a read without narrowing, local to
			//      the file: a `publicClient(overrides: Partial<PublicClient>)`
			//      helper whose spread makes every required field optional, and
			//      `result.tokens` read off a `GrantResult` after a `status`
			//      check that narrows nothing (26 and 22 sites).
			exclude: [
				"src/__tests__/grant.test.mts", // 28: F
				"src/__tests__/hardening.test.mts", // 23: F
			],
			tsconfig: "./tsconfig.test.json",
		},
	},
});
