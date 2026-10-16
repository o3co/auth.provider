import { acrEntries } from "@mod/acr";
import { defineModule } from "@mod/kernel";
import { factors, secondFactorAmr } from "@mod/mfa";

/** The acr clients have asked for a second factor by; an operator may name it otherwise. */
export const acr = "urn:o3co:acr:mfa";

export default defineModule({ name: "mfa-acr" }, (m) => [
	m.contribute(acrEntries).by(async (c) => {
		// Asked for only so boot is refused where no second factor is composed; the value goes unused.
		await c.get(factors);
		return { acr, sets: [[secondFactorAmr]] };
	}),
]);
