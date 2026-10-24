import { contract, extensionPoint } from "@mod/kernel";

export { canonicalAddress, isAddress } from "./address.ts";
export { plainText } from "./plain-text.ts";
export { type Prepared, preparer } from "./prepare.ts";

export type MailValues = Readonly<Record<string, string>>;

export interface Message {
	/** Named by the sending side, which declares it through `mailPurposes`. */
	readonly purpose: string;
	/** Exactly one address. */
	readonly to: string;
	readonly values: MailValues;
	readonly locale?: string;
	/** Kernel clock time from which the message must no longer be delivered. */
	readonly expiresAt?: number;
}

export interface Mail {
	/**
	 * "limited" when the sender's limits refuse it. Throws Unavailable when it cannot be delivered
	 * (also once it has expired), never with the remote side's words; a TypeError for a bad message.
	 */
	send(message: Message): Promise<"sent" | "limited">;
}

export const mail = contract<Mail>("mail");

export interface MailPurpose {
	readonly purpose: string;
}

/** The purposes a sending side uses; each needs a template, or boot is refused. */
export const mailPurposes = extensionPoint<MailPurpose>("mail.purposes", {
	multiplicity: "keyed",
	keyOf: (p) => p.purpose,
});

export interface Rendered {
	/** One line. */
	readonly subject: string;
	readonly text: string;
}

export interface MailTemplate {
	readonly purpose: string;
	render(values: MailValues, locale?: string): Rendered;
}

/** The wording per purpose; a deployment replaces the module that contributes it. */
export const mailTemplates = extensionPoint<MailTemplate>("mail.templates", {
	multiplicity: "keyed",
	keyOf: (t) => t.purpose,
});

/** What `preparer` takes from other modules: a sender's module names these in its takes. */
export const preparerTakes = [mailTemplates, mailPurposes] as const;
