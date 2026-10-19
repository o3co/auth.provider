import { auditEvents } from "@mod/audit";

/** What refresh records; a token, its secret or a family's name is never held. */
export default auditEvents({
	"refresh.family_revoked": {
		attributes: ["client"],
		when: "a refresh token is used again (one already rotated, or the same one twice at once) and its family is revoked, with the subject",
	},
});
