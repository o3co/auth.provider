import { auditEvents } from "@mod/audit";

/** What a caller records through `recordRefusedAuthentication`; the client id claimed and the credentials are never held. */
export default auditEvents({
	"client.authentication.failure": {
		attributes: ["source", "reason"],
		when: "a caller records a client's refused authentication, before any client is known: the token, introspection, revocation and device authorization endpoints, and federation-grants' client routes; with `reason` (`no_credentials`, `multiple_methods`, `malformed_credentials`, `unknown_client`, `wrong_method`, `bad_credentials` or `invalid_record`); the client id claimed is never named",
	},
});
