import { auditEvents } from "@mod/audit";

/** What the witnessing records, with the subject; never a token. */
export default auditEvents({
	"mfa.enrollment_inconsistent": {
		attributes: ["at"],
		when: "the witness marks a subject holding no counting factor, so its store may have lost them; `at` is the decision answered unavailable: `login`, `binding` or `credentials`",
	},
});
