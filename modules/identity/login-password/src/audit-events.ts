import { auditEvents } from "@mod/audit";

/** What a password login records; the subject only when the password matched. */
export default auditEvents({
	"login.succeeded": { attributes: ["method", "source"], when: "a login is answered done" },
	"login.held": {
		attributes: ["method", "source"],
		when: "a login is held by a gate before it is done",
	},
	"login.failed": { attributes: ["method", "source"], when: "a login fails, never saying why" },
});
