import { auditEvents } from "@mod/audit";

/** What the verification interface records, each with the subject and the request's `source` when known; never a code. */
export default auditEvents({
	"device.approved": {
		attributes: ["client", "scope", "source"],
		when: "a code is approved; `scope` space-joined",
	},
	"device.denied": { attributes: ["client", "scope", "source"], when: "a code is denied" },
	"device.approval_refused": {
		attributes: ["client", "policy", "reason", "source"],
		when: "an issuance policy refuses an approval",
	},
	"device.rate_limited": {
		attributes: ["action", "source"],
		when: "the subject is over its attempt limit",
	},
	"device.decision_outcome_unknown": {
		attributes: ["action", "client", "source"],
		when: "a decision's write fails and may or may not have landed",
	},
});
