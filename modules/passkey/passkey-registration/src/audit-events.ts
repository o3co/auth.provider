import { auditEvents } from "@mod/audit";

/** What passkey registration records; a credential's id, nickname or ceremony is never held. */
export default auditEvents({
	"passkey.registered": {
		attributes: ["source"],
		when: "a passkey is kept for the session's subject, the event's subject",
	},
});
