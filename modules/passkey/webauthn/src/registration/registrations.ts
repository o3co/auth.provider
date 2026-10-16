import { challengeOf } from "../ceremony/ceremony.ts";
import type { Ceremonies, RegistrationRefusal, Registrations, Verification } from "../contract.ts";
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
			return kept === "registered"
				? { kind: "registered", credential: attested.credential }
				: refused(kept);
		},
	};
}
