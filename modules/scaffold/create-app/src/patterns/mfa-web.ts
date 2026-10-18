import type { Pattern } from "./pattern.ts";
import { simpleWeb } from "./simple-web.ts";

export const mfaWeb: Pattern = {
	name: "mfa-web",
	use:
		"Simple-web with a second factor: a one-time password app (TOTP), a code by email, and " +
		"recovery codes. Its store is in Redis, since losing it loses the factors users have " +
		"registered; mail goes through an SMTP relay.",
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
	conformanceAdd: [],
};
