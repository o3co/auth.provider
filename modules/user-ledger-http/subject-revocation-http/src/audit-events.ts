import { auditEvents } from "@mod/audit";

/** What the ledger's revocation route records. */
export default auditEvents({
	"subject.revocation.requested": {
		attributes: ["delegations", "outcome", "source"],
		when: "the ledger's revocation of a subject was recorded, or its boundary not confirmed",
	},
	"subject.revocation.denied": {
		attributes: ["reason", "source"],
		when: "a request to revoke a subject was refused before anything was recorded",
	},
});
