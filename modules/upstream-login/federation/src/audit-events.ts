import { auditEvents } from "@mod/audit";

export default auditEvents({
	"federation.login.succeeded": {
		attributes: ["idp", "source"],
		when: "a login through the IdP opened, with the local subject",
	},
	"federation.login.held": {
		attributes: ["idp", "source"],
		when: "a gate held the login, with the local subject",
	},
	"federation.login.failed": {
		attributes: ["idp", "source", "reason"],
		when: "the callback refused the login, with why (`reason`)",
	},
	"federation.identity.linked": {
		attributes: ["idp", "source", "userAgent"],
		when: "a link's callback tied the upstream identity to the subject it started for",
	},
	"federation.identity.link_refused": {
		attributes: ["idp", "source", "userAgent", "reason"],
		when: "a link's callback refused to tie it, with the subject it started for and why (`reason`)",
	},
});
