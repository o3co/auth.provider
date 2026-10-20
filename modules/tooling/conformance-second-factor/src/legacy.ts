import { randomBytes } from "node:crypto";
import { onLegacy } from "@mod/conformance-legacy";
import { secondFactorArea } from "./area.ts";

onLegacy(secondFactorArea, {
	map: (part) => ({
		// Memory stores are refused outside development and test names, so they go to Redis.
		env: {
			MFA_MODE: part.mode,
			MFA_ENCRYPTION_KEY: randomBytes(32).toString("base64"),
			MFA_ENROLLMENT_REQUIRE_EMAIL_PROOF: "never",
			ADAPTERS_MFA_FACTOR_STORE: "redis",
			ADAPTERS_MFA_TRANSACTION_STORE: "redis",
			// A mail sender is wired with MFA; without the mail part nothing is sent, so its address is never reached.
			STANDARD_SMTP_MAIL_SENDER_HOST: part.mail?.host ?? "127.0.0.1",
			STANDARD_SMTP_MAIL_SENDER_PORT: String(part.mail?.port ?? 25),
			STANDARD_SMTP_MAIL_SENDER_FROM: "conformance@issuer.example",
			// The fake SMTP server speaks plain SMTP at loopback, which the sender takes only when told.
			...(part.mail
				? {
						MFA_EMAIL_FACTOR_ENABLED: "true",
						// As on the new target, its proof adds `mfa`.
						MFA_EMAIL_FACTOR_ADDS_MFA: "true",
						STANDARD_SMTP_MAIL_SENDER_SECURE: "none",
					}
				: {}),
		},
		// The lockout's numbers have no variables: the configuration file holds them.
		settings: part.lockout
			? `mfa.lockout { threshold = ${part.lockout.threshold}, baseSeconds = ${part.lockout.backoffSeconds}, maxSeconds = ${part.lockout.maxBackoffSeconds ?? part.lockout.backoffSeconds}, weeklyBudget = ${part.lockout.budget}, hardLimit = ${part.lockout.hardLimit} }\n`
			: "",
	}),
	differs: [
		// A login a second factor held loses where it was going back to.
		"mfa-login-loses-return-target",
	],
});
