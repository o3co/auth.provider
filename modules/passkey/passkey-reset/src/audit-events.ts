import { auditEvents } from "@mod/audit";

/** What a reset records; it has no request, so no source. */
export default auditEvents({
	"passkey.reset": {
		attributes: ["by", "count", "sessions", "sessionsAgain", "complete", "requestedBy"],
		when: "an operator's passkey reset gets past its input, finished or not (`complete`)",
	},
});
