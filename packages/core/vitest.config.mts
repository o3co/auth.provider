import { defineConfig } from "vitest/config";
import { WORKSPACE_TEST_TIMEOUTS } from "../../vitest.shared.mts";

export default defineConfig({
	test: {
		// #357: the workspace-wide deadline floor — rationale in vitest.shared.mts.
		...WORKSPACE_TEST_TIMEOUTS,
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
