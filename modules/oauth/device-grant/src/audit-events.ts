import { auditEvents } from "@mod/audit";

/** What the verification interface records, with the request's `source` when known, and the subject unless one erased is refused; never a code. */
export default auditEvents({
	"device.approved": {
		attributes: ["client", "scope", "source"],
		when: "a code is approved; `scope` space-joined",
	},
	"device.denied": { attributes: ["client", "scope", "source"], when: "a code is denied" },
	"device.approval_refused": {
		attributes: ["client", "policy", "reason", "outcome", "withheld", "source"],
		when: "an approval is refused: by an issuance policy (`policy`, `reason`, with the subject), or, its subject erased, `outcome` `subject_unknown` and `withheld` `erased`, with no subject",
	},
	"device.rate_limited": {
		attributes: ["action", "source"],
		when: "the subject is over its attempt limit",
	},
	"device.decision_outcome_unknown": {
		attributes: ["action", "client", "source"],
		when: "a decision's write, or the write keeping its approval, fails and may or may not have landed",
	},
});
