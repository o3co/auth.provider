import { auditEvents } from "@mod/audit";

export default auditEvents({
	"federation.grant.requested": {
		attributes: ["client", "connection", "outcome", "source"],
		when: "a client lodges an intent, for a new grant (`initial`) or a renewal (`reauthorization`)",
	},
	"federation.grant.request.denied": {
		attributes: ["client", "outcome", "source"],
		when: "a client's intent is refused, with why (`outcome`)",
	},
	"federation.grant.authorized": {
		attributes: ["client", "connection", "outcome", "source"],
		when: "the user connects a new grant, with the identity check that applied (`outcome`)",
	},
	"federation.grant.reauthorized": {
		attributes: ["client", "connection", "outcome", "source"],
		when: "the user connects a renewal, with the identity check that applied (`outcome`)",
	},
	"federation.grant.authorization_failed": {
		attributes: ["client", "connection", "outcome", "source"],
		when: "a connection fails, with why (`outcome`)",
	},
	"federation.grant.revoke.denied": {
		attributes: ["client", "reason", "source"],
		when: "a client's revoke is refused before the grant is found, with why (`reason`), by the client only",
	},
	"federation.grant.token.success": {
		attributes: ["client", "connection", "refreshed", "source"],
		when: "a client is handed a grant's upstream token, refreshed first or not (`refreshed`)",
	},
	"federation.grant.token.denied": {
		attributes: ["client", "connection", "reason", "source"],
		when: "a client is refused a grant's token or renewal, with why (`reason`); by the client only before the grant is found",
	},
	"federation.grant.revoked": {
		attributes: ["client", "connection", "outcome", "source"],
		when: "a grant ends, revoked by its client or by the subject's revocation (`outcome`)",
	},
});
