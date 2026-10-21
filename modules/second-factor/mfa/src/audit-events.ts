import { auditEvents } from "@mod/audit";

/** What mfa records, each with the subject, once written; never for a refused or raced decision but a first binding refused, nor a reset. */
export default auditEvents({
	"mfa.factor.enrolled": { attributes: ["kind", "factor"], when: "a factor is bound" },
	"mfa.factor.removed": { attributes: ["kind", "factor"], when: "a factor is removed" },
	"mfa.recovery_code.used": {
		attributes: ["kind", "factor", "remaining"],
		when: "a recovery code is used; `remaining` when the kind tells how many are left",
	},
	"mfa.first_binding_conflict": {
		attributes: ["kind", "reason"],
		when: "a first binding is refused, at its start or as it is written; nothing is kept. `reason` `competing`: another counting factor counts, bound since it began or held already for a binding asked from a login; `reset-cleared`: a reset took the factor as it was written",
	},
	"mfa.recovery_codes.generated": {
		attributes: ["kind", "regenerated"],
		when: "recovery codes are written by a reissue: a first set after a first counting factor, or one replacing the set held (`regenerated`)",
	},
});
