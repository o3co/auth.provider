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
});
