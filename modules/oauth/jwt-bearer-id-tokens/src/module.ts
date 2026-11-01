import { idTokenChecks } from "@mod/exchange-id-tokens";
import { type DelegatedCheck, delegatedAssertions } from "@mod/jwt-bearer";
import { defineModule, Unavailable } from "@mod/kernel";

const declaredBy = "jwt-bearer-id-tokens";

export default defineModule(
	{ name: "jwt-bearer-id-tokens", replicaSafe: true, takes: [idTokenChecks] },
	(m) => [
		// exchange-id-tokens' issuers, delegated to its checks: the id_tokens go to jwt-bearer as assertions.
		m.contribute(delegatedAssertions).by(async (c) => {
			const checks = await c.get(idTokenChecks);
			return {
				declaredBy,
				issuers: checks.issuers,
				check: async (assertion): Promise<DelegatedCheck> => {
					const taken = await checks.check(assertion);
					if (taken.kind !== "taken") return { kind: "invalid" };
					const { subject, issuedAt, standingAt, expiresAt, client, holderDigest } = taken;
					return {
						kind: "valid",
						subject,
						issuedAt,
						// Where its own check compared the boundary, its skew its own: jwt-bearer's never moves it later.
						standingAt,
						expiresAt,
						clients: [client],
						...(holderDigest === undefined ? {} : { holderDigest }),
					};
				},
				spend: async (assertion) => {
					const told = await checks.consume(assertion);
					if (told === "consumed") return "spent";
					if (told === "replayed") return "replayed";
					throw new Unavailable(declaredBy);
				},
			};
		}),
	],
);
