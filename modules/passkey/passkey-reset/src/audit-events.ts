import { auditEvents } from "@mod/audit";

/** What a reset records; it has no request, so no source. */
export default auditEvents({
	"passkey.reset": {
		attributes: ["by", "count", "sessions", "sessionsAgain", "complete", "requestedBy", "withheld"],
		when: "an operator's passkey reset gets past its input, finished or not (`complete`); without the subject, `withheld` `unread`, where no boundary step answered",
	},
	"passkey.reset.refused": {
		attributes: ["by", "complete", "requestedBy"],
		when: "an operator's passkey reset of a subject a boundary step read as erased, naming no subject; `complete` as that step's `record` answered it, false meaning running it again finishes what this run left",
	},
});
