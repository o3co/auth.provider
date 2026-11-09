/** The purposes this module sends, each declared to `mail`; a wording module contributes a template for each. */
export const purposes = {
	accountEmail: "mfa-email-proof.account-email",
} as const;

export type Purpose = (typeof purposes)[keyof typeof purposes];
