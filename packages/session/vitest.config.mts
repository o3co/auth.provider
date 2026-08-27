import { defineConfig } from "vitest/config";

export default defineConfig({
	test: {
		include: ["src/**/__tests__/**/*.test.mts"],
		// Not because anything here is slow. `pnpm -r run test` runs every
		// workspace's vitest concurrently, and `packages/redis` starts a Redis
		// testcontainer per test file; on a saturated box the transform+import of
		// a test file can itself exceed vitest's 5s default, and tests here fail
		// with "Test timed out" on nothing more than `await import("#/index.mjs")`
		// — a machine-load artifact reported as a product failure. Which test
		// loses the race varies run to run, which is the tell.
		//
		// `packages/redis` already carries an override for the same reason
		// (container boot). Raising the deadline does not hide a real hang: a
		// genuinely stuck test still fails, 15s later.
		testTimeout: 20_000,
		hookTimeout: 20_000,
		typecheck: {
			enabled: true,
			// Scoped to A5 redirect-policy / contributes-map / slim type-only tests.
			// Pre-existing federation tests (supportsLogout / types / factory /
			// Federation.test) intentionally use partial FederationProfile mocks
			// that don't satisfy strict typecheck — broadening the include would
			// require retrofitting them with `expiresAt: null` etc. (out of A5
			// scope; tracked as a separate cleanup for the existing test debt).
			include: [
				"src/federations/__tests__/redirect-policy-types.test.mts",
				"src/federations/__tests__/redirect-policy.test.mts",
				"src/federations/__tests__/contributes-map-augment.test.mts",
				"src/federations/__tests__/federation-provider-slim.test.mts",
				"src/routes/__tests__/federation-rewire.test.mts",
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
