import { type Ceremonies, type Credential, challengeOf, type Verification } from "@mod/webauthn";
import type { KeptChallenges } from "../challenges/challenges.ts";
import type { RegistrationRefusal, Registrations } from "../contract.ts";
import type { Asked } from "../holders/holders.ts";
import type { Emptied, KeptPasskeys } from "../records.ts";

export interface RegistrationParts {
	readonly ceremonies: Ceremonies;
	readonly records: KeptPasskeys;
	readonly challenges: KeptChallenges;
	readonly verification: Verification;
	/** The passkeys a subject may hold. */
	readonly max: number;
	/** A new subject's handle: 32 random bytes, unpadded base64url. */
	freshHandle(): string;
	/** Brings the witness's mark in line after a write; `emptied`, the holder left, where this call emptied the list. */
	settle(subject: string, at: Asked, emptied?: Emptied): Promise<unknown>;
}

const refused = (reason: RegistrationRefusal) => ({ kind: "refused" as const, reason });

/**
 * What the caller's check answers, having `undo` run where it says no or throws, at once or later; a
 * throw is passed on once `undo` was tried, as that failure is the answer whether or not `undo` could run.
 */
async function settled(
	check: () => Promise<boolean>,
	undo: () => Promise<unknown>,
): Promise<boolean> {
	let admitted: boolean;
	try {
		admitted = await check();
	} catch (error) {
		await undo().catch(() => undefined);
		throw error;
	}
	if (!admitted) await undo();
	return admitted;
}

/** Registrations of passkeys, each answering a challenge made for its subject. */
export function registrationsOver(p: RegistrationParts): Registrations {
	/**
	 * Keeps an attested credential, its record and its listing written as one: asked before the
	 * write, so a revoked registration writes nothing, and once more after it.
	 */
	const joined = async (
		subject: string,
		credential: Credential,
		nickname: string | undefined,
		challengedAt: number,
		admitted: (challengedAt: number) => Promise<boolean>,
	) => {
		if (!(await admitted(challengedAt))) return refused("revoked");
		// Made before the write, so a write sent again writes the same token, and an end can name it.
		const written = p.records.writeToken();
		/** Ends what this write left, if it was written: off the list, its record stripped, and settled. */
		const end = async () => {
			const removed = await p.records.ended(subject, credential.id, written);
			await p.settle(subject, "removal", removed.emptied);
		};
		// A write whose answer is lost may have landed: ended, as no ask after it can run.
		const wrote = await p.records
			.joined(subject, credential, p.max, nickname, written)
			.catch(async (error) => {
				await end().catch(() => undefined);
				throw error;
			});
		if (wrote !== "written") return refused(wrote);
		// Once more, written and listed: a revocation landing between the first ask and the write ends it.
		if (!(await settled(() => admitted(challengedAt), end))) return refused("revoked");
		// Usable only now, both asks having admitted. Not this write's record any more (removed or cleared): nothing registered.
		if ((await p.records.activated(credential.id, written)) !== "activated") {
			await end();
			return refused("conflict");
		}
		// The mark follows the write; one that cannot be set leaves the passkey as written.
		await p.settle(subject, "registration");
		return { kind: "registered" as const, credential, challengedAt };
	};
	return {
		creation: async (subject) => {
			const handle = await p.records.handleFor(subject, p.freshHandle());
			const held = (await p.records.holder(subject))?.credentials ?? [];
			const made = p.ceremonies.creation({ handle, name: subject }, held, p.verification);
			await p.challenges.open(made.challenge, { kind: "registration", subject });
			return { options: made.options };
		},
		register: async (subject, response, nickname, admitted = async () => true) => {
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
			const { credential } = attested;
			return joined(subject, credential, nickname, opened.at, admitted);
		},
		listed: (subject) => p.records.listed(subject),
		renamed: (subject, id, nickname) => p.records.renamed(subject, id, nickname),
		removed: async (subject, id) => {
			const removed = await p.records.removed(subject, id);
			// Only the call whose own update emptied the list may withdraw a mark it did not set.
			await p.settle(subject, "removal", removed.emptied);
			// The holder it left stays inside: its handle is the subject's.
			return { removed: removed.removed, empty: removed.empty };
		},
	};
}
