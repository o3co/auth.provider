import type { Rendered } from "@mod/mail";
import { type Purpose, purposes } from "@mod/mfa-email-proof";

const unasked = "If you did not ask for this, someone may know your password: change it.";

/** The wording of each mail, in English for every locale. */
export const wordings = {
	[purposes.accountEmail]: {
		subject: "Confirm your email address",
		text: `Your code to confirm this email address is {code}.\nIt expires in {minutes} minute(s).\n\n${unasked}\n`,
	},
} as const satisfies Readonly<Record<Purpose, Rendered>>;
