import { auditEvents } from "@mod/audit";

export default auditEvents({
	"logout.success": {
		attributes: ["sid", "source", "userAgent"],
		when: "a logout a client started closed the session it names",
	},
	// logout's own kind, declared alike here: one kind, one meaning.
	"logout.close_pending": {
		attributes: ["sid", "source"],
		when: "the session is closed but some of its close work is left for later",
	},
	"logout.cascade_failed": {
		attributes: ["sid", "source", "userAgent", "store"],
		when: "a logout a client started could not close the session (`store`: the module whose close failed)",
	},
});
