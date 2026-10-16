import type { Pattern } from "./pattern.ts";

export const a2a: Pattern = {
	name: "a2a",
	use:
		"Tokens between services, with no user and no login: clients authenticate by a signed " +
		"assertion or a secret, take client credentials or a JWT bearer grant from a trusted issuer, " +
		"and may bind their tokens to a certificate (mTLS) or a key (DPoP).",
	axes: {
		"@mod/store": "@mod/store",
		"@mod/audit": "@mod/audit",
		"@mod/mail": "@mod/mail",
	},
	features: {
		grants: ["@mod/jwt-bearer"],
		"client-auth": ["@mod/client-assertion"],
		binding: ["@mod/mtls", "@mod/dpop"],
	},
	areas: ["keys", "oauth", "mtls", "ops"],
	conformanceAdd: ["@mod/token-exchange"],
};
