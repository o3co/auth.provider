import { defineModule } from "@mod/kernel";
import { erasureFence, erasureGuards, subjectRevocation } from "@mod/subject-revocation";
import { issuanceFences, subjectChecks } from "@mod/tokens";

export default defineModule(
	{ name: "subject-tokens", replicaSafe: true, takes: [subjectRevocation, erasureFence] },
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
		// A bundle of credentials passes only where its subject is not erased, by one fenced write.
		m.contribute(issuanceFences).by(async (c) => {
			const fence = await c.get(erasureFence);
			return {
				name: "subject-tokens",
				fence: async ({ subject, receiptId }) =>
					(await fence.fence(subject, receiptId)) === "passed" ? "passed" : "refused",
			};
		}),
		// Where tokens composes this module, access tokens are checked and issuance fenced on this boundary.
		m.contribute(erasureGuards).by(() => ({ name: "subject-tokens" })),
	],
);
