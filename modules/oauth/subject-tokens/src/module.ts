import { defineModule } from "@mod/kernel";
import { subjectRevocation } from "@mod/subject-revocation";
import { subjectChecks } from "@mod/tokens";

export default defineModule(
	{ name: "subject-tokens", replicaSafe: true, takes: [subjectRevocation] },
	(m) => [
		// An access token is an authentication of its subject at its standing time: its grant's check, else its issue.
		m.contribute(subjectChecks).by(async (c) => {
			const revocation = await c.get(subjectRevocation);
			return {
				holds: async (token) =>
					(await revocation.check(token.subject, token.standingAt)) === "valid"
						? "holds"
						: "revoked",
			};
		}),
	],
);
