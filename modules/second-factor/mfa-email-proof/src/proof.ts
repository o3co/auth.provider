import { longCode, type MailedCodes, readLongCode } from "@mod/account-mail-code";
import { type Log, Unavailable } from "@mod/kernel";
import type { BindingProof } from "@mod/mfa-binding-proof";
import type { Users } from "@mod/users";
import { z } from "zod";
import { proofName } from "./name.ts";
import { purposes } from "./purposes.ts";

/** How long the proof before a first binding stays good, at most. */
const proofMs = 600_000;

/** What a proof keeps: the address, the code mailed there, and when it stops being good. */
const keptShape = z.strictObject({
	code: z.string().min(1),
	until: z.number(),
	address: z.string().min(1),
});

/** A kept value; one there but unreadable is a failure, never a wrong code. */
const read = (text: string): z.output<typeof keptShape> => {
	const parsed = (() => {
		try {
			return keptShape.safeParse(JSON.parse(text));
		} catch {
			return undefined;
		}
	})();
	if (!parsed?.success) throw new Unavailable("mfa-email-proof");
	return parsed.data;
};

export interface ProofParts {
	/** `account-mail-code`'s rules for the address, mailing the code and checking it typed back. */
	readonly mailed: MailedCodes;
	readonly users: Pick<Users, "verifiedContact">;
	readonly log: Pick<Log, "warn">;
	readonly now: () => number;
	readonly random: (n: number) => Uint8Array;
}

/** The proof of the account's address before a first binding: a long code mailed there. */
export function accountEmailProof(p: ProofParts): BindingProof {
	const { mailed } = p;
	return {
		name: proofName,
		available: async (subject, from) => (await mailed.addressNow(subject, from)) !== undefined,
		send: async (subject, latest, from) => {
			const address = await mailed.addressNow(subject, from);
			if (!address) return { kind: "refused" };
			const code = longCode(p.random);
			const until = Math.min(p.now() + proofMs, latest);
			const sent = await mailed.send(purposes.accountEmail, address, code, until);
			if (sent.kind !== "sent") return sent;
			return { ...sent, kept: JSON.stringify({ address, code, until }) };
		},
		check: async (subject, kept, given) => {
			const asked = read(kept);
			if (!mailed.matches(asked, readLongCode(given))) return false;
			// The code reached the address: users keeps it as the subject's, where it keeps any more.
			try {
				await p.users.verifiedContact(subject, { kind: "email", value: asked.address });
			} catch (error) {
				// Past users' limit the proof still stands: keeping the address only records it.
				if (!(error instanceof RangeError)) throw error;
				// The name operators know from when mfa-email held the proof.
				p.log.warn("mfa-email.contact_not_kept", { reason: "limit" });
			}
			return true;
		},
	};
}
