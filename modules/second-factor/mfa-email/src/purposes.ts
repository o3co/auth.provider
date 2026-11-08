/** The purposes this module declares to `mail`; a wording module contributes a template for each. */
export const purposes = {
	enrollment: "mfa-email.enrollment",
	login: "mfa-email.login",
	proof: "mfa-email.proof",
} as const;

export type Purpose = (typeof purposes)[keyof typeof purposes];
