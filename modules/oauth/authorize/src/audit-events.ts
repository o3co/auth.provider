import { auditEvents } from "@mod/audit";

/** What the authorization endpoint records of its decisions; never the code, `state`, the redirect URI or the scope. */
export default auditEvents({
	"authorize.granted": {
		attributes: ["client", "source", "response_type"],
		when: "a code is given, with the subject and `response_type` `code`",
	},
	"authorize.rejected": {
		attributes: ["client", "source", "reason", "policy"],
		when: "a refusal decided for the client or its consent, with no subject and its `reason` (`grant_type_not_allowed`, `scope_omitted_without_default`, `client_not_first_party`, `consent_required`, or an issuance policy's reason with `policy` its name)",
	},
});
