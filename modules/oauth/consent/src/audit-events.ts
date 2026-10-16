import { auditEvents } from "@mod/audit";

/** What consent records, with the subject. */
export default auditEvents({
	"consent.granted": {
		attributes: ["client", "scopes", "source"],
		when: "a consent is granted; `scopes` space-joined",
	},
	"consent.denied": {
		attributes: ["client", "scopes", "source"],
		when: "a consent is denied; `scopes` space-joined",
	},
});
