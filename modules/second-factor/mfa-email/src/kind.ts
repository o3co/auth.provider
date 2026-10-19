import { sameSecret, Unavailable } from "@mod/kernel";
import type { Mail } from "@mod/mail";
import type { BindingProof } from "@mod/mfa-binding-proof";
import type { AskedFrom, FactorKind, Opened, Sending } from "@mod/mfa-extensions";
import type { SubjectAttributes } from "@mod/subject-attributes";
import { type Users, userAttribute } from "@mod/users";
import { z } from "zod";
import { addressOf, masked } from "./address.ts";
import { longCode, readLongCode, readShortCode, shortCode } from "./codes.ts";
import { type Purpose, purposes } from "./contract.ts";

/** How long the proof before a first binding stays good, at most. */
const proofMs = 600_000;

/** A code kept for its proof: the code, and when it stops being good (epoch ms on `kernel`'s clock). */
const keptShape = z.strictObject({ code: z.string().min(1), until: z.number() });
/** A factor's secret, or a proof's kept code: the address, and the code mailed there. */
const secretShape = keptShape.extend({ address: z.string().min(1) });
type Kept = z.output<typeof keptShape>;
const keep = (code: string, until: number) => JSON.stringify({ code, until } satisfies Kept);

/** A stored value; one there but unreadable is a failure, never an answer (no attempt is spent on it). */
const read = <T>(shape: z.ZodType<T>, text: string | undefined): T | undefined => {
	if (text === undefined) return undefined;
	const parsed = (() => {
		try {
			return shape.safeParse(JSON.parse(text));
		} catch {
			return undefined;
		}
	})();
	if (!parsed?.success) throw new Unavailable("mfa-email");
	return parsed.data;
};

export interface EmailParts {
	readonly mail: Pick<Mail, "send">;
	readonly users: Pick<Users, "claimedContacts" | "verifiedContact">;
	/** A session's login attributes, and whether `users` vouches for them. */
	readonly attributes: () => Pick<SubjectAttributes, "of">;
	readonly addsSecondFactor: boolean;
	readonly codeMs: number;
	readonly now: () => number;
	readonly random: (n: number) => Uint8Array;
}

export function emailFactor(p: EmailParts) {
	/**
	 * The address `users` stands behind now: the one the account states, else the one the login (held,
	 * or the session's) gave when `users` vouches for it (an outside ledger's answer). Never an upstream's: its
	 * account's taker could set the address and get the codes. None when there is no such address.
	 */
	const addressNow = async (subject: string, from?: AskedFrom) => {
		const contacts = await p.users.claimedContacts(subject);
		const claimed = Array.isArray(contacts) ? contacts.find((c) => c.kind === "email") : undefined;
		if (claimed) return addressOf(claimed.value);
		if (from?.kind === "login")
			return from.vouched && from.email ? addressOf(from.email) : undefined;
		if (from?.kind !== "session") return undefined;
		const answer = await p.attributes().of(subject, from.handle);
		const email =
			answer.kind === "known" && answer.vouched && answer.attributes[userAttribute.email];
		return typeof email === "string" ? addressOf(email) : undefined;
	};
	/** Mails the code, good until `until`: sent, with what the user is shown and what to keep, or limited. */
	const mailCode = async (
		purpose: Purpose,
		to: string,
		code: string,
		until: number,
	): Promise<Sending> => {
		const minutes = String(Math.max(1, Math.ceil((until - p.now()) / 60_000)));
		const answer = await p.mail.send({ purpose, to, values: { code, minutes }, expiresAt: until });
		if (answer === "limited") return { kind: "limited" };
		// Read again after the send: the page shows what is left once the mail went.
		const seconds = Math.max(1, Math.ceil((until - p.now()) / 1000));
		const show = { sent_to: masked(to), expires_in: seconds };
		return { kind: "sent", show, kept: keep(code, until) };
	};
	/** Whether `typed`, read as its kind of code, is the kept code, before its end. */
	const answers = (kept: Kept | undefined, typed: string | undefined) =>
		kept !== undefined &&
		typed !== undefined &&
		p.now() <= kept.until &&
		sameSecret(typed, kept.code);

	const kind: FactorKind = {
		kind: "email",
		amr: ["email"],
		addsSecondFactor: p.addsSecondFactor,
		guessable: true,
		counts: true,
		enroll: async (subject, held: readonly Opened[], from) => {
			const address = await addressNow(subject, from);
			if (!address) return { kind: "refused" };
			// Checked before anything is sent: a second factor at the address the subject already holds.
			if (held.some((factor) => read(secretShape, factor.secret)?.address === address)) {
				return { kind: "duplicate" };
			}
			const code = longCode(p.random);
			const until = p.now() + p.codeMs;
			const mailed = await mailCode(purposes.enrollment, address, code, until);
			if (mailed.kind !== "sent") return mailed;
			return { secret: JSON.stringify({ address, code, until }), show: mailed.show };
		},
		challenge: async (subject, factor, latest, from): Promise<Sending> => {
			const address = read(secretShape, factor.secret)?.address;
			if (!address) throw new Unavailable("mfa-email");
			// An address the account no longer states is never sent to: its contact changed.
			if (address !== (await addressNow(subject, from))) {
				return { kind: "refused", reason: "contact-changed" };
			}
			const code = shortCode(p.random);
			return mailCode(purposes.login, address, code, Math.min(p.now() + p.codeMs, latest));
		},
		verify: async (secret, state, proof, kept) => {
			if (state === null) {
				// A binding's first proof is the long code its secret holds.
				const right = answers(read(secretShape, secret), readLongCode(proof));
				return right ? { kind: "valid", state: {} } : { kind: "invalid" };
			}
			const right = answers(read(keptShape, kept), readShortCode(proof));
			return right ? { kind: "valid", state } : { kind: "invalid" };
		},
	};

	const proof: BindingProof = {
		name: "account-email",
		available: async (subject, from) => (await addressNow(subject, from)) !== undefined,
		send: async (subject, latest, from) => {
			const address = await addressNow(subject, from);
			if (!address) return { kind: "refused" };
			const code = longCode(p.random);
			const until = Math.min(p.now() + proofMs, latest);
			const mailed = await mailCode(purposes.proof, address, code, until);
			if (mailed.kind !== "sent") return mailed;
			return { ...mailed, kept: JSON.stringify({ address, code, until }) };
		},
		check: async (subject, kept, given) => {
			const asked = read(secretShape, kept);
			if (!asked || !answers(asked, readLongCode(given))) return false;
			// The code reached the address: users keeps it as the subject's.
			await p.users.verifiedContact(subject, { kind: "email", value: asked.address });
			return true;
		},
	};
	return { kind, proof };
}
