import type { Pattern } from "./pattern.ts";

export const simpleWeb: Pattern = {
	name: "simple-web",
	use:
		"A web login by password for clients that use the authorization code flow with refresh; " +
		"services that use client credentials add it (--add @mod/client-credentials). It needs no " +
		"outside system: the store is kept in memory, users are listed in the configuration, and " +
		"audit events go to the log.",
	axes: {
		"@mod/store": "@mod/store",
		"@mod/users": "@mod/users",
		"@mod/audit": "@mod/audit",
		"@mod/mail": "@mod/mail",
	},
	features: {
		login: [
			"@mod/login-password",
			"@mod/login-gates",
			"@mod/csrf",
			"@mod/session",
			"@mod/logout",
			"@mod/rp-logout",
		],
		grants: [
			"@mod/authorize",
			"@mod/code-grant",
			"@mod/consent",
			"@mod/oidc",
			"@mod/acr",
			"@mod/session-tokens",
			"@mod/refresh",
			"@mod/userinfo",
		],
	},
	areas: ["keys", "identity", "code", "oauth", "ops"],
	// The token endpoint's own checks (client authentication, introspection, CORS, DPoP) take its tokens.
	conformanceAdd: ["@mod/client-credentials"],
};
