import { auditEvents } from "@mod/audit";

/** What the token endpoint records; a token or secret is never held. */
export default auditEvents({
	"token.issued": {
		attributes: ["client", "source", "grant_type", "claims", "claims_left"],
		when: "a grant issues; `claims` names the claims the grant added to the tokens it issued, in their order, one space apart, never their values: all of them within 2048 characters, else as many as fit, with `claims_left` how many were left out",
	},
	"token.issued.failure": {
		attributes: ["client", "source", "grant_type", "reason", "error", "policy", "refusal"],
		when: "a request is refused, with `reason` (`repeated_parameter`, `mistyped_parameter`, `missing_grant_type`, `unsupported_grant_type`, `grant_type_not_allowed`, `unsupported_body`, `multiple_bindings`, `binding_refused`, `binding_required`, `binding_kind_not_named`, `untargeted`, `grant_refused`, or `issuance_refused` with the refusing `policy` and its `refusal`) and the answer's `error`; `grant_type` once it is known",
	},
});
