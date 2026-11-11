import { auditEvents } from "@mod/audit";

/** What refresh records; a token, its secret or a family's name is never held. */
export default auditEvents({
	"refresh.family_revoked": {
		attributes: ["client", "withheld"],
		when: "a refresh token is used again (one already rotated, or the same one twice at once) and its family is revoked, with the subject; without it, `withheld` `erased` where the subject is erased, or `unread` where that could not be read",
	},
});
