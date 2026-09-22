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
			// itself when typecheck was switched on (187 in 32 files, of 62).
			// They are named here rather than hidden behind a narrower glob, as
			// core does for `InMemoryClientRepository.test.mts`, with the count
			// at exclusion and the cause. The same list is the `exclude` of
			// tsconfig.test.json, which has to keep them out of tsc's program.
			// TODO(#626): remove a file as its cause is fixed. The causes:
			//
			//  [R] `new GrantRegistry()` (core's `./testing` entry) handed to
			//      `createOAuthRouter`, whose `registry` is a
			//      `GrantHandlerResolver`; the class has `get` but not `entries`.
			//      One cause, 48 sites in 27 files, and the only error in 16 of
			//      them. Its fix is a core change (an `entries()` on the class,
			//      or a narrower `routes` contract), not a test edit.
			//  [S] `code_client_id` written into `SessionData` fixtures. D-1
			//      (v0.5.1) removed the field from the type; the runtime never
			//      reads it. 59 sites in 4 files.
			//  [F] a partial mock or a stale fixture shape local to the file
			//      (a `vi.fn()` without its signature, a missing `type` import,
			//      a `GrantResult` read without narrowing, a `Map` fixture that
			//      infers `never[]`).
			exclude: [
				"src/__tests__/allowedGrantTypes.enforcement.test.mts", // 1: R
				"src/__tests__/authorization.test.mts", // 54: S
				"src/__tests__/authorizationCode.userinfo.integration.test.mts", // 2: S, F
				"src/__tests__/authorizeEndpoint.test.mts", // 11: R, F
				"src/__tests__/clientCredentials.integration.test.mts", // 3: R, F
				"src/__tests__/clientIdMetadataDocument.authorize.test.mts", // 1: R
				"src/__tests__/consent.test.mts", // 13: R, F
				"src/__tests__/dpop.clientCredentials.integration.test.mts", // 2: R, F
				"src/__tests__/emailVerifiedGate.integration.test.mts", // 1: R
				"src/__tests__/firstPartyAuthorize.test.mts", // 2: R
				"src/__tests__/hooks.test.mts", // 16: R, S, F
				"src/__tests__/introspect.audience.test.mts", // 1: R
				"src/__tests__/introspect.revocationOutage.test.mts", // 1: R
				"src/__tests__/introspect.sessionLiveness.test.mts", // 1: R
				"src/__tests__/introspectCascade.test.mts", // 1: R
				"src/__tests__/issuer.integration.test.mts", // 1: R
				"src/__tests__/jwtBearer.test.mts", // 31: F
				"src/__tests__/module.test.mts", // 3: F
				"src/__tests__/mtls.clientCredentials.integration.test.mts", // 2: R, F
				"src/__tests__/oauthAuthorization.test.mts", // 7: R, S, F
				"src/__tests__/pkceMandatory.integration.test.mts", // 1: R
				"src/__tests__/resourceIndicator.stage2.authorize.test.mts", // 2: R, F
				"src/__tests__/resourceIndicator.stage2.test.mts", // 10: F
				"src/__tests__/revoke.introspect.integration.test.mts", // 1: R
				"src/__tests__/routes.test.mts", // 8: R
				"src/__tests__/senderConstrained.integration.test.mts", // 3: R, F
				"src/__tests__/sessionGrant.logout.integration.test.mts", // 1: R
				"src/__tests__/sessionGrant.security.test.mts", // 1: R
				"src/__tests__/subjectRevocation.wiring.test.mts", // 1: R
				"src/__tests__/tokenBinding.dispatchPolicy.integration.test.mts", // 2: R, F
				"src/__tests__/tokenBinding.integration.test.mts", // 1: R
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
