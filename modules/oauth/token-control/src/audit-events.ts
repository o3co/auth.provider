import { auditEvents } from "@mod/audit";

/** What token control records; a revocation never holds the token. */
export default auditEvents({
	"introspect.store_unavailable": {
		attributes: ["source"],
		when: "introspection is answered unavailable",
	},
	"token.revoked": {
		attributes: ["client", "source", "token_type"],
		when: "a revocation is written; `token_type` is the kind's hint",
	},
});
