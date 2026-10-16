import { auditEvents } from "@mod/audit";

/** What mfa records, each with the subject, once written; never for a refused or raced decision, nor a reset. */
export default auditEvents({
	"mfa.factor.enrolled": { attributes: ["kind", "factor"], when: "a factor is bound" },
	"mfa.factor.removed": { attributes: ["kind", "factor"], when: "a factor is removed" },
	"mfa.recovery_code.used": {
		attributes: ["kind", "factor", "remaining"],
		when: "a recovery code is used; `remaining` when the kind tells how many are left",
	},
	"mfa.recovery_codes.generated": {
		attributes: ["kind", "regenerated"],
		when: "recovery codes come with a first counting factor, or are reissued (`regenerated`)",
	},
});
