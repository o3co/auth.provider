import type { Pattern } from "./pattern.ts";
import { simpleWeb } from "./simple-web.ts";

export const mfaWeb: Pattern = {
	name: "mfa-web",
	use:
		"Simple-web with a second factor: a one-time password app (TOTP) and recovery codes, the " +
		"account's address proved by a code mailed there before a first binding. A code by email as " +
		"a factor is added (`--add @mod/mfa-email`) and counts as one only where its " +
		"`adds-second-factor` is set. Its store is in Redis, since losing it loses the factors users " +
		"have registered; mail goes through an SMTP relay.",
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
			"@mod/mfa-email-proof",
			"@mod/mfa-recovery",
		],
	},
	areas: ["keys", "identity", "code", "oauth", "second-factor", "ops"],
	// The token endpoint's own checks (client authentication, introspection, CORS, DPoP) take its tokens.
	conformanceAdd: ["@mod/client-credentials"],
};
