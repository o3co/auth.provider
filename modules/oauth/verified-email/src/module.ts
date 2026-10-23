import { clientCredentialsGrantType } from "@mod/client-credentials";
import { defineModule } from "@mod/kernel";
import { subjectAttributes } from "@mod/subject-attributes";
import { type IssuanceVerdict, issuancePolicies } from "@mod/tokens";
import { userAttribute } from "@mod/users";

const allowed: IssuanceVerdict = Object.freeze({ kind: "allowed" });
const unverified: IssuanceVerdict = Object.freeze({
	kind: "refused",
	reason: "email_not_verified",
	description: "email address is not verified",
});

export default defineModule({ name: "verified-email" }, (m) => [
	m.contribute(issuancePolicies).by((c) => {
		// Late: subject-attributes needs sessions, and sessions get tokens while being built, so an early get would cycle.
		const attributes = c.late(subjectAttributes);
		return {
			name: "verified-email",
			judge: async ({ grant, grantType, session, continuing }) => {
				// A continuing issuance follows one already judged; client credentials name no user.
				if (continuing || grantType === clientCredentialsGrantType) return allowed;
				const found = await attributes().of(grant.subject, session);
				// Only users' word: an upstream verified an address that need not be this user's.
				const stated =
					found.kind === "known" &&
					found.vouched &&
					found.attributes[userAttribute.emailVerified] === true;
				return stated ? allowed : unverified;
			},
		};
	}),
]);
