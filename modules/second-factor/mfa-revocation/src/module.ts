import { defineModule } from "@mod/kernel";
import { fenceFollower } from "@mod/mfa";
import { factorManaging } from "@mod/mfa-managing";
import { revocationFollowers } from "@mod/subject-revocation";

export default defineModule(
	{ name: "mfa-revocation", replicaSafe: true, takes: [factorManaging] },
	(m) => [
		m.contribute(revocationFollowers).by(async (c) => {
			const decided = await c.get(factorManaging);
			return { name: fenceFollower, follow: (subject) => decided.fence(subject) };
		}),
	],
);
