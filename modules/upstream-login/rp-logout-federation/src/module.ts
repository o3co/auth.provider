import { upstreamEndSessions } from "@mod/federation-tokens";
import { defineModule } from "@mod/kernel";
import { upstreamEnds } from "@mod/rp-logout";

export default defineModule(
	{ name: "rp-logout-federation", replicaSafe: true, takes: [upstreamEndSessions] },
	(m) => [
		m.contribute(upstreamEnds).by(async (c) => {
			const ends = await c.get(upstreamEndSessions);
			return {
				name: "federation-tokens",
				at: async (session, back) => {
					try {
						return await ends.of(session, back);
					} catch (error) {
						// The logout goes on without the upstream; only the error's type is logged.
						const type = error instanceof Error ? error.name : typeof error;
						c.log.warn("rp-logout-federation.end_failed", { error: type });
						return undefined;
					}
				},
			};
		}),
	],
);
