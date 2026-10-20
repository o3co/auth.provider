import { auditEvents } from "@mod/audit";

/** What a reset records; it has no request, so no source. */
export default auditEvents({
	"mfa.reset": {
		attributes: ["by", "kinds", "count", "sessions", "sessionsAgain", "complete", "requestedBy"],
		when: "an operator's reset gets past its input, finished or not (`complete`)",
	},
});
