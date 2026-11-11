import { defineModule } from "@mod/kernel";
import { fenceFollower } from "@mod/mfa";
import { factorManaging } from "@mod/mfa-managing";
import { revocationFollowers } from "@mod/subject-revocation";

export default defineModule(
	{ name: "mfa-revocation", replicaSafe: true, takes: [factorManaging] },
	(m) => [
		m.contribute(revocationFollowers).by(async (c) => {
			const decided = await c.get(factorManaging);
			return {
				name: fenceFollower,
				// An erased subject's bindings are refused already, and a fence would create a factor list under it.
				follow: async (subject, { erased }) => {
					if (!erased) await decided.fence(subject);
				},
			};
		}),
	],
);
