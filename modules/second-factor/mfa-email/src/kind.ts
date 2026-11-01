import { Unavailable } from "@mod/kernel";
import type { Mail } from "@mod/mail";
import type { FactorKind, Opened, Sending } from "@mod/mfa-extensions";
import type { SubjectAttributes } from "@mod/subject-attributes";
import type { Users } from "@mod/users";
import { z } from "zod";
import { longCode, readLongCode, readShortCode, shortCode } from "./codes.ts";
import { mailedCodes } from "./mailed.ts";
import { purposes } from "./purposes.ts";

/** A code kept for its proof: the code, and when it stops being good (epoch ms on `kernel`'s clock). */
const keptShape = z.strictObject({ code: z.string().min(1), until: z.number() });
/** A factor's secret: the address, and the code mailed there. */
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
	readonly users: Pick<Users, "claimedContacts">;
	/** A session's login attributes, and whether `users` vouches for them. */
	readonly attributes: () => Pick<SubjectAttributes, "of">;
	readonly addsSecondFactor: boolean;
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

	return kind;
}
