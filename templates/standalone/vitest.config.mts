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
		// #512: run the @o3co/auth-provider-* packages through vitest instead of
		// letting Node load them natively. In a scaffolded project they are
		// installed from npm under node_modules, which vitest externalizes by
		// default — and an externalized package's own `import "ioredis"` /
		// `import "redis"` never sees a `vi.mock` from a test file, so
		// replica-safety.test.mts dialled a Redis that is not there. Inside the
		// monorepo the same packages are symlinks to source and are inlined
		// anyway; this makes the two layouts behave the same.
		server: { deps: { inline: [/@o3co\/auth-provider-/] } },
	},
});
