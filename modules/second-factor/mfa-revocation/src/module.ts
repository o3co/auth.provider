import { defineModule } from "@mod/kernel";
import { factors } from "@mod/mfa";
import { revocationFollowers } from "@mod/subject-revocation";

export default defineModule({ name: "mfa-revocation" }, (m) => [
	m.contribute(revocationFollowers).by(async (c) => {
		const decided = await c.get(factors);
		return { name: "mfa", follow: (subject) => decided.fence(subject) };
	}),
]);
