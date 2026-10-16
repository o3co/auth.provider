import { auditEvents } from "@mod/audit";

/** What a logout records, with the session's subject where it names one. */
export default auditEvents({
	"logout.succeeded": {
		attributes: ["sid", "source"],
		when: "a logout is answered done, with or without a session",
	},
	"logout.close_pending": {
		attributes: ["sid", "source"],
		when: "the session is closed but some of its close work is left for later",
	},
});
