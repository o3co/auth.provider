import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

export default defineConfig({
	resolve: {
		alias: {
			"#/": fileURLToPath(new URL("./src/", import.meta.url)),
		},
	},
	test: {
		include: ["src/**/__tests__/**/*.test.mts"],
		server: {
			deps: {
				// Externalize workspace packages so Node resolves their internal
				// #/* subpath imports via their own package.json imports field.
				external: [/@o3co\/auth-provider-/, /packages\/(core|oauth|session|did)/],
			},
		},
	},
});
