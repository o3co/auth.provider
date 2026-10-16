import { auditEvents } from "@mod/audit";

export default auditEvents({
	"federation.token.succeeded": {
		attributes: ["idp", "client", "refreshed", "source"],
		when: "the calling client is handed the upstream token, refreshed first or not (`refreshed`)",
	},
	"federation.token.failed": {
		attributes: ["idp", "client", "reason", "source"],
		when: "the calling client is refused the upstream token (`reason`); not when unlinked, limited or a 503",
	},
	"federation.logout.succeeded": {
		attributes: ["idp", "client", "redirected", "source"],
		when: "a session is logged out of the IdP, sent on to its end of session or not (`redirected`)",
	},
});
