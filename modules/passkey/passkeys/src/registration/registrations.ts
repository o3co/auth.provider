import { type Ceremonies, challengeOf, type Verification } from "@mod/webauthn";
import type { RegistrationRefusal, Registrations } from "../contract.ts";
import type { Asked } from "../holders/holders.ts";
import type { KeptChallenges, KeptPasskeys } from "../records.ts";

export interface RegistrationParts {
	readonly ceremonies: Ceremonies;
	readonly records: KeptPasskeys;
	readonly challenges: KeptChallenges;
	readonly verification: Verification;
	/** The passkeys a subject may hold. */
	readonly max: number;
	/** A new subject's handle: 32 random bytes, unpadded base64url. */
	freshHandle(): string;
	/** Brings the witness's mark in line after a write; `emptied` where this call emptied the list. */
	settle(subject: string, at: Asked, emptied?: boolean): Promise<unknown>;
}

const refused = (reason: RegistrationRefusal) => ({ kind: "refused" as const, reason });

/** Registrations of passkeys, each answering a challenge made for its subject. */
export function registrationsOver(p: RegistrationParts): Registrations {
	return {
		creation: async (subject) => {
			const handle = await p.records.handleFor(subject, p.freshHandle());
			const held = (await p.records.holder(subject))?.credentials ?? [];
			const made = p.ceremonies.creation({ handle, name: subject }, held, p.verification);
			await p.challenges.open(made.challenge, { kind: "registration", subject });
			return { options: made.options };
		},
		register: async (subject, response, nickname) => {
			const challenge = challengeOf(response);
			if (challenge === undefined) return refused("unreadable");
			const opened = await p.challenges.take(challenge);
			const holder = await p.records.holder(subject);
			if (opened?.kind !== "registration" || opened.subject !== subject || !holder) {
				return refused("no-challenge");
			}
			const attested = await p.ceremonies.attest(
				response,
				challenge,
				holder.handle,
				p.verification,
			);
			if (attested.kind === "refused") return attested;
			const kept = await p.records.register(subject, attested.credential, p.max, nickname);
			if (kept !== "registered") return refused(kept);
			// The mark follows the write; one that cannot be set leaves the passkey as written.
			await p.settle(subject, "registration");
			return { kind: "registered", credential: attested.credential, challengedAt: opened.at };
		},
		listed: (subject) => p.records.listed(subject),
		renamed: (subject, id, nickname) => p.records.renamed(subject, id, nickname),
		removed: async (subject, id) => {
			const removed = await p.records.removed(subject, id);
			// Only the call whose own update emptied the list may clear a mark it did not set.
			await p.settle(subject, "removal", removed.removed && removed.empty);
			return removed;
		},
	};
}
