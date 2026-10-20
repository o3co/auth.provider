import { auditEvents } from "@mod/audit";

/** What the token endpoint records, and `authenticateClient` for every endpoint using it; a token or secret is never held. */
export default auditEvents({
	"client.authentication.failure": {
		attributes: ["source", "reason"],
		when: "a client's authentication is refused, before any client is known, with `reason` (`no_credentials`, `multiple_methods`, `malformed_credentials`, `unknown_client`, `wrong_method`, `bad_credentials` or `invalid_record`); the client id claimed is never named",
	},
	"token.issued": {
		attributes: ["client", "source", "grant_type"],
		when: "a grant issues",
	},
	"token.issued.failure": {
		attributes: ["client", "source", "grant_type", "reason", "error", "policy", "refusal"],
		when: "a request is refused, with `reason` (`repeated_parameter`, `mistyped_parameter`, `missing_grant_type`, `unsupported_grant_type`, `grant_type_not_allowed`, `unsupported_body`, `multiple_bindings`, `binding_refused`, `binding_required`, `binding_kind_not_named`, `untargeted`, `grant_refused`, or `issuance_refused` with the refusing `policy` and its `refusal`) and the answer's `error`; `grant_type` once it is known",
	},
});
