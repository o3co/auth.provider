import { auditEvents } from "@mod/audit";

/** What rate limiting records. */
export default auditEvents({
	"rate_limit.unavailable": {
		attributes: ["limit", "name", "source", "outcome"],
		when: "a policy cannot count",
	},
});
