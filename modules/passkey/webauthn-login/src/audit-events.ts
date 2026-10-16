import { auditEvents } from "@mod/audit";

export default auditEvents({
	"passkey.login.refused": {
		attributes: ["client", "reason"],
		when: "a passkey assertion is not accepted, with why (`reason`, a kind from a fixed list)",
	},
});
