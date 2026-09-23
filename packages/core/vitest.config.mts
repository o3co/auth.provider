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
				// D-1 FOLLOW-UP: explicit single-file include (not the
				// `repositories/__tests__/**` glob) because
				// `InMemoryClientRepository.test.mts` has 16 pre-existing TS
				// errors unrelated to D-1. Widen to the glob once that file
				// is cleaned up — track in the next core/repositories
				// hygiene PR.
				"src/repositories/__tests__/InMemoryCodeRepository.test.mts",
				// #343: this file's fixtures use `satisfies Required<...>` to make
				// a new optional field on `Client` / `User` a COMPILE error rather
				// than a silently uncovered one. That only fires under typecheck
				// mode, and `tsconfig.json` excludes `__tests__` — so without this
				// line the annotation is decorative, which is the same
				// looks-enforced-but-is-not shape #343 is about.
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
				// v0.13.0 audit: never typechecked before; paired with tsconfig.test.json.
				"src/challenges/__tests__/types.test.mts",
				"src/challenges/__tests__/wiring.test.mts",
				// #593: the `@ts-expect-error` directives here are the regression
				// test for the FederationGrant union — a revoked or pending grant
				// with only some of the authorization fields must not compile.
				"src/federation-grants/__tests__/types.test.mts",
				// Which AssertionIssuerEntry fields a registry must not drop. Paired
				// with the same entry in tsconfig.test.json — both lists, or nothing.
				"src/assertions/__tests__/entry-fields.types.test.mts",
				// The registry's own tests and the verifier's — their fixtures build
				// entries, and went uncompiled while claiming a type they did not
				// satisfy. Paired with tsconfig.test.json.
				"src/assertions/__tests__/issuerRegistry.test.mts",
				"src/assertions/__tests__/registryAssertionVerifier.test.mts",
				// #645 follow-up: which `FederationTokens` fields a store must not
				// drop. A conditional-type assertion proves nothing outside the checker.
				"src/federation-tokens/__tests__/record-fields.types.test.mts",
				// Their fixtures build `FederationTokens` records, and went
				// uncompiled while missing keys the type requires. Paired with
				// tsconfig.test.json.
				"src/federation-tokens/__tests__/memory.test.mts",
				"src/federation-tokens/__tests__/removeBySid-rename.test.mts",
				// #626 P1: relocated from `packages/session`, where both were in its
				// typecheck list. The `expectTypeOf` and `@ts-expect-error` here
				// are the regression test for the adapter port, and they only fire
				// under typecheck mode — moving the files without moving the
				// entries would have left them transpiled and unchecked.
				"src/federations/__tests__/federation-provider-slim.test.mts",
				"src/federations/__tests__/delegated-authorization-types.test.mts",
				// #626 P2: `GrantDependencies` is pinned to ComponentMap slot types.
				// Paired with tsconfig.test.json, as #343 requires.
				"src/grants/__tests__/dependencies.types.test.mts",
				// #626: which consent-record fields a store must not drop, and the
				// fixtures that build those records — uncompiled, they went on
				// omitting a field the type now requires. Paired with
				// tsconfig.test.json.
				"src/consents/__tests__/**/*.test.mts",
				// #626: which Code fields a repository must not drop, and a factory
				// test that builds one — uncompiled, it went on omitting the keys.
				// Paired with tsconfig.test.json.
				"src/repositories/__tests__/code-fields.types.test.mts",
				"src/repositories/__tests__/createRepositoryFactories.test.mts",
				// #626: which DeviceAuthorization fields a store must not drop, and
				// the fixtures that build them. Paired with tsconfig.test.json.
				"src/device-authorization/__tests__/**/*.test.mts",
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
