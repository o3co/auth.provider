import { defineConfig } from "vitest/config";
import { WORKSPACE_TEST_SETUP, WORKSPACE_TEST_TIMEOUTS } from "../../vitest.shared.mts";

export default defineConfig({
	test: {
		// #357: the workspace-wide deadline floor — rationale in vitest.shared.mts.
		...WORKSPACE_TEST_TIMEOUTS,
		// #556: supertest's server binds the loopback address it dials — see vitest.shared.mts.
		...WORKSPACE_TEST_SETUP,
		include: ["src/**/__tests__/**/*.test.mts"],
		typecheck: {
			enabled: true,
			include: [
				"src/modules/manifest/**/*.test.mts",
				"src/boot/**/*.test.mts",
				"src/refresh-token-family/**/*.test.mts",
				"src/user-sessions/__tests__/**/*.test.mts",
				// Its fixtures build `CreateCodeInput`, which names every key.
				"src/repositories/__tests__/InMemoryCodeRepository.test.mts",
				// This file's fixtures use `satisfies Required<...>` to make a new
				// optional field on `Client` / `User` a compile error rather than a
				// silently uncovered one; listed so that error is reported against
				// its own tests.
				"src/repositories/__tests__/entrySchemaConformance.test.mts",
				// CC-5 readonly compile-time contract tests. The @ts-expect-error
				// directives in these files only fire under typecheck mode.
				"src/__tests__/grant-context-readonly.test.mts",
				"src/__tests__/repository-types-readonly.test.mts",
				// AS-7 deprecation alias type-equivalence assertions.
				"src/__tests__/naming-aliases.test.mts",
				// AS-M1 contributes-map concrete-type substitution assertions.
				"src/__tests__/contributes-map-substitution.test.mts",
				// Wave 1 §2.3.1 — WebAuthnCredential + WebAuthnCredentialStore type contract.
				"src/webauthn-credentials/__tests__/types.test.mts",
				// The challenge store's type contract, and `wiring.test.mts`'s
				// `satisfies … as BootstrapMap`.
				"src/challenges/__tests__/types.test.mts",
				"src/challenges/__tests__/wiring.test.mts",
				// #593: the `@ts-expect-error` directives here are the regression
				// test for the FederationGrant union — a revoked or pending grant
				// with only some of the authorization fields must not compile.
				"src/federation-grants/__tests__/types.test.mts",
				// The session-admission ADR (A2): the contract's shapes are asserted
				// with expectTypeOf, and the fixtures claim the port's types.
				"src/session-admission/**/*.test.mts",
				// Which intent fields a store must not drop.
				"src/federation-grants/__tests__/intent-fields.types.test.mts",
				// Which grant fields a store must not drop.
				"src/federation-grants/__tests__/record-fields.types.test.mts",
				// Which AssertionIssuerEntry fields a registry must not drop.
				"src/assertions/__tests__/entry-fields.types.test.mts",
				// The registry's own tests and the verifier's: their fixtures build
				// entries that claim the entry type.
				"src/assertions/__tests__/issuerRegistry.test.mts",
				"src/assertions/__tests__/registryAssertionVerifier.test.mts",
				// #645 follow-up: which `FederationTokens` fields a store must not
				// drop. A conditional-type assertion proves nothing outside the checker.
				"src/federation-tokens/__tests__/record-fields.types.test.mts",
				// Their fixtures build `FederationTokens` records, which name every
				// key the type requires.
				"src/federation-tokens/__tests__/memory.test.mts",
				"src/federation-tokens/__tests__/removeBySid-rename.test.mts",
				// The `expectTypeOf` and `@ts-expect-error` here are the regression
				// test for the adapter port, and they fire only under typecheck mode.
				"src/federations/__tests__/federation-provider-slim.test.mts",
				"src/federations/__tests__/delegated-authorization-types.test.mts",
				// `GrantDependencies` is pinned to ComponentMap slot types.
				"src/grants/__tests__/dependencies.types.test.mts",
				// Which consent-record fields a store must not drop, and the
				// fixtures that build those records.
				"src/consents/__tests__/**/*.test.mts",
				// Which Code fields a repository must not drop, and a factory test
				// that builds one.
				"src/repositories/__tests__/code-fields.types.test.mts",
				"src/repositories/__tests__/createRepositoryFactories.test.mts",
				// Which DeviceAuthorization fields a store must not drop, and the
				// fixtures that build them.
				"src/device-authorization/__tests__/**/*.test.mts",
				// One type per audit `details` key: `error` a string, `cause` an
				// audited error.
				"src/audit/__tests__/audit-details.types.test.mts",
				// The MFA ports: the slot and contract assertions here are
				// `expectTypeOf`, and the fixtures build records whose every field is
				// a required key.
				"src/mfa/__tests__/**/*.test.mts",
				"src/mail/__tests__/**/*.test.mts",
				// The MFA enrollment witness on `User` and `UserRepository`.
				"src/repositories/__tests__/mfaEnrollmentWitness.test.mts",
				// The slots through which modules share what one of them owns: the
				// slot types are asserted with expectTypeOf, and the fixtures claim
				// the contracts' types.
				"src/token-settings/__tests__/**/*.test.mts",
				"src/browser-session/__tests__/**/*.test.mts",
				"src/deployment/__tests__/**/*.test.mts",
				// The RateLimiter port's `failMode` and its contract suite (#728).
				"src/ratelimit/__tests__/rateLimiter.contract.test.mts",
				// The outage policy's brand and options.
				"src/ratelimit/__tests__/policy.types.test.mts",
				// The rate-limit guard: its fixtures claim the `Logger` and
				// `RateLimiter` types.
				"src/ratelimit/__tests__/guard.test.mts",
			],
			// vitest 5 collects a typecheck-included file's tests from the file
			// itself, where 4 was content to let an imported helper register
			// them. These five call a shared contract runner and declare nothing
			// locally, so the typecheck pass reports "No test suite found in
			// file"; none of them asserts a type either. Every other file in the
			// globs above — `wiring.test.mts` and its `satisfies … as
			// BootstrapMap` contract included — stays.
			exclude: [
				"src/refresh-token-family/__tests__/adapters.memory.test.mts",
				"src/user-sessions/__tests__/memory.sessionFamilyIndex.test.mts",
				"src/user-sessions/__tests__/memory.sessionFederationIndex.test.mts",
				"src/user-sessions/__tests__/memory.sessionRPRegistry.test.mts",
				"src/user-sessions/__tests__/memory.userSessionStore.test.mts",
			],
			// tsconfig.test.json, not the build config: the build config leaves
			// `__tests__` out. Its program takes every file under `src`. In any
			// run that includes one of the files `include` above names (a full
			// run, and CI, always does), an error in any file of the program
			// fails the run; `include` decides only which files' errors are
			// reported against their own tests.
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
