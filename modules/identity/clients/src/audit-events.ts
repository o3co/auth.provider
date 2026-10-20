import { auditEvents } from "@mod/audit";

/** What a caller records through `recordRefusedAuthentication`; the client id claimed and the credentials are never held. */
export default auditEvents({
	"client.authentication.failure": {
		attributes: ["source", "reason"],
		when: "a client's authentication is refused, before any client is known, with `reason` (`no_credentials`, `multiple_methods`, `malformed_credentials`, `unknown_client`, `wrong_method`, `bad_credentials` or `invalid_record`); the client id claimed is never named",
	},
});
