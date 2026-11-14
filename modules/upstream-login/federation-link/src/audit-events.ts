import { auditEvents } from "@mod/audit";

export default auditEvents({
	"federation.identity.linked": {
		attributes: ["idp", "source", "userAgent"],
		when: "a link's callback tied the upstream identity to the subject it started for",
	},
	"federation.identity.link_refused": {
		attributes: ["idp", "source", "userAgent", "reason"],
		when: "a link's callback refused to tie it, and why (`reason`), with the subject it started for while the session it started in still lives",
	},
});
