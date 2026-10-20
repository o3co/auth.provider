import { auditEvents } from "@mod/audit";

export default auditEvents({
	"mfa.challenge.sent": {
		attributes: ["kind", "purpose", "source"],
		when: "a factor's or a binding proof's challenge is sent",
	},
	"mfa.verified": {
		attributes: ["kind", "factor", "purpose", "source"],
		when: "a factor (`factor`) or a binding proof (`kind`) is proved, once the transaction is taken",
	},
	"mfa.verify.failure": {
		attributes: ["kind", "factor", "purpose", "reason", "source"],
		when: "a factor (`factor`) or a binding proof (`kind`) is not proved, with why (`reason`)",
	},
	"mfa.locked": {
		attributes: ["factor", "purpose", "hold", "source"],
		when: "a proof is refused while the subject is locked out (`hold`)",
	},
	"mfa.locked.first": {
		attributes: ["factor", "purpose", "hold", "source"],
		when: "a wrong guess starts a hold (`hold`)",
	},
	"mfa.email_address_mismatch": {
		attributes: ["kind", "purpose", "source"],
		when: "a kind refuses a factor whose contact changed",
	},
	"mfa.lock.recovered": {
		attributes: ["operation", "generation", "week", "run", "hard", "source"],
		when: "a user's release of their lockout clears something",
	},
});
