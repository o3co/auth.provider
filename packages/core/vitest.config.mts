import { defineConfig } from "vitest/config";

export default defineConfig({
	test: {
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
