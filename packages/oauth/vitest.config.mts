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
		// it. The glob is the rule. Paired with tsconfig.test.json, and both
		// lists are needed, as core's config explains.
		typecheck: {
			enabled: true,
			include: ["src/**/__tests__/**/*.test.mts"],
			// Every file below carried pre-existing type errors in the test
			// itself when typecheck was switched on (187 in 32 files, of 62;
			// 16 files have since been cleared, see [R]). They are named here
			// rather than hidden behind a narrower glob, as core does for
			// `InMemoryClientRepository.test.mts`, with the count at exclusion
			// and the cause. The same list is the `exclude` of
			// tsconfig.test.json, which has to keep them out of tsc's program.
			// TODO(#626): remove a file as its cause is fixed. The causes:
			//
			//  [R] `new GrantRegistry()` (core's `./testing` entry) handed to
			//      `createOAuthRouter`, whose `registry` was a whole
			//      `GrantHandlerResolver` while the router reads only `get`.
			//      Closed by narrowing the router's contract to
			//      `Pick<GrantHandlerResolver, "get">` (#626); the 16 files
			//      whose only cause it was are typechecked again. The files
			//      still marked R below carry another cause as well.
			//  [S] `code_client_id` written into `SessionData` fixtures. D-1
			//      (v0.5.1) removed the field from the type; the runtime never
			//      reads it. 59 sites in 4 files.
			//  [F] a partial mock or a stale fixture shape local to the file
			//      (a `vi.fn()` without its signature, a missing `type` import,
			//      a `GrantResult` read without narrowing, a `Map` fixture that
			//      infers `never[]`).
			exclude: [
				"src/__tests__/authorization.test.mts", // 54: S
				"src/__tests__/authorizationCode.userinfo.integration.test.mts", // 2: S, F
				"src/__tests__/authorizeEndpoint.test.mts", // 11: R, F
				"src/__tests__/clientCredentials.integration.test.mts", // 3: R, F
				"src/__tests__/consent.test.mts", // 13: R, F
				"src/__tests__/dpop.clientCredentials.integration.test.mts", // 2: R, F
				"src/__tests__/hooks.test.mts", // 16: R, S, F
				"src/__tests__/jwtBearer.test.mts", // 31: F
				"src/__tests__/module.test.mts", // 3: F
				"src/__tests__/mtls.clientCredentials.integration.test.mts", // 2: R, F
				"src/__tests__/oauthAuthorization.test.mts", // 7: R, S, F
				"src/__tests__/resourceIndicator.stage2.authorize.test.mts", // 2: R, F
				"src/__tests__/resourceIndicator.stage2.test.mts", // 10: F
				"src/__tests__/senderConstrained.integration.test.mts", // 3: R, F
				"src/__tests__/tokenBinding.dispatchPolicy.integration.test.mts", // 2: R, F
				"src/__tests__/tokenBinding.introspect.integration.test.mts", // 2: R, F
			],
			tsconfig: "./tsconfig.test.json",
		},
		coverage: {
			provider: "v8",
			reporter: ["text", "json", "json-summary"],
			reportsDirectory: "./coverage",
			include: ["src/**/*.mts"],
			exclude: ["src/**/__tests__/**", "src/**/*.d.mts", "dist/**"],
			all: true,
		},
	},
});
