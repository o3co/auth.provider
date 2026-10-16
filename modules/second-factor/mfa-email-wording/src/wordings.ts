import type { Rendered } from "@mod/mail";
import { type Purpose, purposes } from "@mod/mfa-email";

const warning = "If you did not try to sign in, someone may know your password: change it.";
const unasked = "If you did not ask for this, someone may know your password: change it.";

/** The wording of each mail, in English for every locale. */
export const wordings = {
	[purposes.login]: {
		subject: "Your sign-in code",
		text: `Your sign-in code is {code}.\nIt expires in {minutes} minute(s).\n\n${warning}\n`,
	},
	[purposes.proof]: {
		subject: "Confirm your email address",
		text: `Your code to confirm this email address is {code}.\nIt expires in {minutes} minute(s).\n\n${unasked}\n`,
	},
	[purposes.enrollment]: {
		subject: "Confirm sign-in codes by email",
		text: `Your code to receive sign-in codes at this address is {code}.\nIt expires in {minutes} minute(s).\n\n${unasked}\n`,
	},
} as const satisfies Readonly<Record<Purpose, Rendered>>;
