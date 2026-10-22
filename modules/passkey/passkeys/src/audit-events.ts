import { auditEvents } from "@mod/audit";

/** What passkeys records, with the subject; never a token or a credential id. */
export default auditEvents({
	"passkey.enrollment_inconsistent": {
		attributes: ["at"],
		when: "the witness marks a subject holding no passkey, so the passkey store may have lost them; `at` is where it was found: `held`, `registration`, `removal`, `reset` or `settle`",
	},
});
