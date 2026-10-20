import { randomBytes } from "node:crypto";
import { type NewPart, onNew } from "@mod/conformance";
import { type SecondFactorPart, secondFactorArea } from "./area.ts";

const setUp = (part: SecondFactorPart): NewPart => ({
	modules: [
		"@mod/seal",
		"@mod/mfa",
		"@mod/mfa-binding-proof",
		"@mod/mfa-flows",
		"@mod/mfa-management",
		"@mod/mfa-totp",
		"@mod/mfa-recovery",
		// The wording is mfa-email's default adapter, which the scene names as it names the rest.
		...(part.mail ? ["@mod/mail-smtp", "@mod/mfa-email", "@mod/mfa-email-wording"] : []),
	],
	store: "volatile",
	config: {
		...(part.lockout
			? {
					"mfa-flows": {
						lockout: {
							threshold: part.lockout.threshold,
							backoff: `${part.lockout.backoffSeconds}s`,
							"max-backoff": `${part.lockout.maxBackoffSeconds ?? part.lockout.backoffSeconds}s`,
							budget: part.lockout.budget,
							"hard-limit": part.lockout.hardLimit,
						},
					},
				}
			: {}),
		mfa: { mode: part.mode },
		// As on legacy, no proof of the address is asked before a first binding.
		...(part.mail ? { "mfa-binding-proof": { mode: "never" } } : {}),
		// The scenes bind a code by mail as a factor that counts, which it is only where its proof adds `mfa`.
		...(part.mail ? { "mfa-email": { "adds-second-factor": true } } : {}),
		...(part.mail
			? {
					"mail-smtp": {
						host: part.mail.host,
						port: part.mail.port,
						security: "none",
						from: "conformance@issuer.example",
					},
				}
			: {}),
		seal: { current: { id: "conformance", key: randomBytes(32).toString("base64") } },
	},
});

onNew(secondFactorArea, setUp);
