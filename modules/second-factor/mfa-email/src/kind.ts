import { type Log, Unavailable } from "@mod/kernel";
import type { Mail } from "@mod/mail";
import type { BindingProof } from "@mod/mfa-binding-proof";
import type { FactorKind, Opened, Sending } from "@mod/mfa-extensions";
import type { SubjectAttributes } from "@mod/subject-attributes";
import type { Users } from "@mod/users";
import { z } from "zod";
import { longCode, readLongCode, readShortCode, shortCode } from "./codes.ts";
import { mailedCodes } from "./mailed.ts";
import { purposes } from "./purposes.ts";

/** How long the proof before a first binding stays good, at most. */
const proofMs = 600_000;

/** A code kept for its proof: the code, and when it stops being good (epoch ms on `kernel`'s clock). */
const keptShape = z.strictObject({ code: z.string().min(1), until: z.number() });
/** A factor's secret, or a proof's kept code: the address, and the code mailed there. */
const secretShape = keptShape.extend({ address: z.string().min(1) });

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
	readonly log: Pick<Log, "warn">;
	readonly codeMs: number;
	readonly now: () => number;
	readonly random: (n: number) => Uint8Array;
}

export function emailFactor(p: EmailParts) {
	const { addressNow, send: mailCode, matches: answers } = mailedCodes(p);

	const kind: FactorKind = {
		kind: "email",
		amr: ["email"],
		addsSecondFactor: p.addsSecondFactor,
		guessable: true,
		// A proof that does not add `mfa` cannot meet a required second factor, so only then does it count.
		counts: p.addsSecondFactor,
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
			// The code reached the address: users keeps it as the subject's, where it keeps any more.
			try {
				await p.users.verifiedContact(subject, { kind: "email", value: asked.address });
			} catch (error) {
				// Past users' limit the proof still stands: keeping the address only records it.
				if (!(error instanceof RangeError)) throw error;
				p.log.warn("mfa-email.contact_not_kept", { reason: "limit" });
			}
			return true;
		},
	};
	return { kind, proof };
}
