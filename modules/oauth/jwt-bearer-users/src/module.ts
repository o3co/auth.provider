import { linkedIssuers, linkedSubjects } from "@mod/jwt-bearer";
import { defineModule } from "@mod/kernel";
import { upstreamNames, users } from "@mod/users";

const declaredBy = "jwt-bearer-users";

export default defineModule({ name: declaredBy }, (m) => [
	m.contribute(linkedSubjects).by(async (c) => {
		const people = await c.get(users);
		return {
			declaredBy,
			subjectOf: async (upstream, sub) => {
				const found = await people.byUpstream(upstream, sub);
				return found.kind === "user"
					? { kind: "subject", subject: found.user.subject }
					: { kind: "none" };
			},
		};
	}),
	m.contribute(upstreamNames).by(async (c) => ({
		declaredBy,
		names: (await c.get(linkedIssuers)).map(({ upstream, issuer }) => ({ name: upstream, issuer })),
	})),
]);
