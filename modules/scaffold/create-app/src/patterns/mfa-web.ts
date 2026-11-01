import type { Pattern } from "./pattern.ts";
import { simpleWeb } from "./simple-web.ts";

export const mfaWeb: Pattern = {
	name: "mfa-web",
	use:
		"Simple-web with a second factor: a one-time password app (TOTP) and recovery codes, and a " +
		"code by email, which counts as one only where mfa-email's `adds-second-factor` is set. " +
		"Its store is in Redis, since losing it loses the factors users have registered; mail goes " +
		"through an SMTP relay.",
	axes: {
		...simpleWeb.axes,
		"@mod/store": "@mod/redis",
		"@mod/mail": "@mod/mail-smtp",
	},
	features: {
		...simpleWeb.features,
		"second-factor": [
			"@mod/mfa",
			"@mod/mfa-flows",
			"@mod/mfa-management",
			"@mod/mfa-acr",
			"@mod/mfa-totp",
			"@mod/mfa-email",
			"@mod/mfa-recovery",
		],
	},
	areas: ["keys", "identity", "code", "oauth", "second-factor", "ops"],
	// The token endpoint's own checks (client authentication, introspection, CORS, DPoP) take its tokens.
	conformanceAdd: ["@mod/client-credentials"],
};
