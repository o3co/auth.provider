import type { Pattern } from "./pattern.ts";
import { simpleWeb } from "./simple-web.ts";

export const ssoFederated: Pattern = {
	name: "sso-federated",
	use:
		"Single sign-on through upstream identity providers (OpenID Connect, Google, GitHub, Apple), " +
		"with no password of its own: clients use the authorization code flow with refresh, and " +
		"services client credentials. Users come from an outside ledger.",
	axes: { ...simpleWeb.axes, "@mod/users": "@mod/users-http" },
	features: {
		login: [
			"@mod/upstreams",
			"@mod/idp-oidc",
			"@mod/idp-google",
			"@mod/idp-github",
			"@mod/idp-apple",
			"@mod/federation-tokens",
			"@mod/logout",
			"@mod/rp-logout",
		],
		grants: simpleWeb.features.grants ?? [],
	},
	areas: ["keys", "identity", "code", "oauth", "federation", "ops"],
	conformanceAdd: ["@mod/login-password"],
};
