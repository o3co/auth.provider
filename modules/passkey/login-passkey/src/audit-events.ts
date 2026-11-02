import { auditEvents } from "@mod/audit";

/** What a passkey login records; never a credential id or anything the request sent. */
export default auditEvents({
	"passkey.session.opened": {
		attributes: ["source"],
		when: "a passkey login opens a session",
	},
	"passkey.session.held": {
		attributes: ["source"],
		when: "a passkey login is held by a gate before its session opens",
	},
	"passkey.session.refused": {
		attributes: ["reason", "source"],
		when: "a passkey login is refused: `reason` is the assertion's refusal, `unknown_user`, `revoked` or `gate_refused`",
	},
	"passkey.password_refused": {
		attributes: ["source"],
		when: "a password login of a subject holding a passkey is refused (`password = refused-when-held`)",
	},
});
