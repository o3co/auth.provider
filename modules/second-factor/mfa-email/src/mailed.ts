import { type BuildContext, sameSecret } from "@mod/kernel";
import { type Mail, mail } from "@mod/mail";
import type { AskedFrom, Sending } from "@mod/mfa-extensions";
import { type SubjectAttributes, subjectAttributes } from "@mod/subject-attributes";
import { type Users, userAttribute, users } from "@mod/users";
import { addressOf, masked } from "./address.ts";
import type { Purpose } from "./purposes.ts";

export interface MailedParts {
	readonly mail: Pick<Mail, "send">;
	readonly users: Pick<Users, "claimedContacts">;
	/** A session's login attributes, and whether `users` vouches for them. */
	readonly attributes: () => Pick<SubjectAttributes, "of">;
	readonly now: () => number;
}

/** A code mailed to the account's address: where it goes, sending it, and checking it typed back. */
export interface MailedCodes {
	/**
	 * The address `users` stands behind now: the one the account states, else the one the login (held,
	 * or the session's) gave when `users` vouches for it. Never an upstream's. None when there is none.
	 */
	addressNow(subject: string, from?: AskedFrom): Promise<string | undefined>;
	/** Mails the code, good until `until`: sent, with what the user is shown and what to keep, or limited. */
	send(purpose: Purpose, to: string, code: string, until: number): Promise<Sending>;
	/** Whether `typed`, read as its kind of code, is the kept code, before its end. */
	matches(
		kept: { readonly code: string; readonly until: number } | undefined,
		typed: string | undefined,
	): boolean;
}

export function mailedCodes(p: MailedParts): MailedCodes {
	return {
		// Never an upstream's address: its account's taker could set the address and get the codes.
		addressNow: async (subject, from) => {
			const contacts = await p.users.claimedContacts(subject);
			const claimed = Array.isArray(contacts)
				? contacts.find((c) => c.kind === "email")
				: undefined;
			if (claimed) return addressOf(claimed.value);
			if (from?.kind === "login")
				return from.vouched && from.email ? addressOf(from.email) : undefined;
			if (from?.kind !== "session") return undefined;
			const answer = await p.attributes().of(subject, from.handle);
			const email =
				answer.kind === "known" && answer.vouched && answer.attributes[userAttribute.email];
			return typeof email === "string" ? addressOf(email) : undefined;
		},
		send: async (purpose, to, code, until) => {
			const minutes = String(Math.max(1, Math.ceil((until - p.now()) / 60_000)));
			const answer = await p.mail.send({
				purpose,
				to,
				values: { code, minutes },
				expiresAt: until,
			});
			if (answer === "limited") return { kind: "limited" };
			// Read again after the send: the page shows what is left once the mail went.
			const seconds = Math.max(1, Math.ceil((until - p.now()) / 1000));
			const show = { sent_to: masked(to), expires_in: seconds };
			return { kind: "sent", show, kept: JSON.stringify({ code, until }) };
		},
		matches: (kept, typed) =>
			kept !== undefined &&
			typed !== undefined &&
			p.now() <= kept.until &&
			sameSecret(typed, kept.code),
	};
}

/** The same, over what the assembly gives: `mail`, `users`, and `subject-attributes` taken late. */
export const mailedCodesIn = async (c: BuildContext<unknown>): Promise<MailedCodes> =>
	mailedCodes({
		mail: await c.get(mail),
		users: await c.get(users),
		// Late: session's own build asks mfa, which asks the kinds and proofs that use this.
		attributes: c.late(subjectAttributes),
		now: c.clock.now,
	});
