import { contract, extensionPoint } from "@mod/kernel";
import type { CeremonyRefusal, Credential } from "@mod/webauthn";

/** Assertions by the discoverable passkeys this package keeps. Throws Unavailable when the store cannot tell. */
export interface Passkeys {
	/** The same for everyone: reads nothing and lists no credential. Only `requester` redeems it. */
	challenge(requester: string): Promise<{ readonly options: unknown }>;
	/** `requester` is who redeems: a challenge made for another is refused as `challenge`. */
	assert(
		response: unknown,
		requester: string,
	): Promise<
		| {
				readonly kind: "asserted";
				readonly subject: string;
				/** When the challenge was made, on `kernel`'s clock. */
				readonly challengedAt: number;
				readonly userVerified: boolean;
				readonly backupEligible: boolean;
		  }
		| {
				readonly kind: "refused";
				readonly reason: CeremonyRefusal | "unknown-credential" | "no-user-handle" | "raced";
		  }
	>;
}

export const passkeys = contract<Passkeys>("passkeys.passkeys");

export type RegistrationRefusal =
	| CeremonyRefusal
	| "unreadable"
	| "no-challenge"
	| "conflict"
	| "full"
	/** The caller's check found a revocation since the challenge was made: nothing of it is kept. */
	| "revoked";

/** Passkeys for a subject the caller vouches for, each answering a challenge made for it, once. Throws Unavailable when the store cannot tell. */
export interface Registrations {
	/** Options for a new passkey of `subject`, excluding its own; its first options make its user handle. */
	creation(subject: string): Promise<{ readonly options: unknown }>;
	/**
	 * `admitted` is asked with when the challenge was made, before the passkey is written, then once
	 * again after it is written and listed: on `false` or a throw, nothing of it stays usable
	 * (`revoked`, or the throw passed on).
	 */
	register(
		subject: string,
		response: unknown,
		nickname?: string,
		admitted?: (challengedAt: number) => Promise<boolean>,
	): Promise<
		| {
				readonly kind: "registered";
				readonly credential: Credential;
				/** When the challenge it answered was made, on `kernel`'s clock. */
				readonly challengedAt: number;
		  }
		| { readonly kind: "refused"; readonly reason: RegistrationRefusal }
	>;
	/** The subject's passkeys, as its holder lists them. */
	listed(subject: string): Promise<readonly RegisteredPasskey[]>;
	/** Names one of the subject's passkeys; none of them by that id is `unknown`. */
	renamed(subject: string, id: string, nickname: string): Promise<"renamed" | "unknown">;
	/** Ends one of the subject's passkeys: `removed` when this call ended it, `empty` when the subject holds none after. */
	removed(
		subject: string,
		id: string,
	): Promise<{ readonly removed: boolean; readonly empty: boolean }>;
}

/** A passkey as its holder lists it: no key or count. `at` is when it was registered, unknown for one kept before that was written. */
export interface RegisteredPasskey {
	readonly id: string;
	readonly nickname?: string;
	readonly transports?: readonly string[];
	readonly backupEligible: boolean;
	readonly backedUp: boolean;
	readonly at?: number;
}

export const registrations = contract<Registrations>("passkeys.registrations");

/** Whether subjects hold passkeys, kept in line with the witness composed. Throws Unavailable when the store or the witness cannot tell. */
export interface PasskeyHolders {
	/** Whether the subject holds a passkey; settled with the witness first, so a mark beside none is unavailable. */
	held(subject: string): Promise<boolean>;
	/** Ends every passkey of the subject, and has its mark go: a reset's. */
	cleared(subject: string): Promise<{ readonly removed: number }>;
	/** Brings the witness's mark in line with the passkeys the subject holds. */
	settle(subject: string): Promise<void>;
	/** Whether a witness is composed, as read at boot. */
	readonly witnessed: boolean;
}

/** Taken by the modules that log in with passkeys and reset them, as it can end every passkey a subject holds. */
export const passkeyHolders = contract<PasskeyHolders>("passkeys.holders", {
	takenBy: ["login-passkey", "passkey-reset"],
});

/** Where a settle was asked, as an inconsistency found there is recorded. */
export type Asked = "held" | "registration" | "removal" | "reset" | "settle";

/**
 * What a subject holds after a write that emptied its list, read anew each time and writing
 * nothing: `passkey` or `pending` where its list names one of the subject's; `none` where the holder
 * is the one that write left, at its fence or later, and every listed record reads as none of the
 * subject's, the only answer under which the mark may go; `unsure` otherwise, which keeps the mark.
 */
export type AfterRemoval = "passkey" | "pending" | "none" | "unsure";

/** Who tells, apart from the store, that a subject holds a passkey: contributed by `passkey-witnessing` where a witness is composed. */
export interface PasskeyWitnessing {
	/** Brings the mark in line with what the subject holds, as `holds` reads it anew; answers whether it holds, as the read the mark agreed with saw it. */
	settle(subject: string, at: Asked, holds: () => Promise<boolean>): Promise<boolean>;
	/** After a write that emptied the list: the mark goes only where `after` answers none, and is set again where a passkey came meanwhile. */
	emptied(
		subject: string,
		at: Asked,
		after: () => Promise<AfterRemoval>,
		holds: () => Promise<boolean>,
	): Promise<void>;
}

/** At most one; with none, passkeys matches the witness composed itself, or the store alone tells. */
export const passkeyWitnessing = extensionPoint<PasskeyWitnessing>("passkeys.witnessing", {
	multiplicity: "many",
});

export { type PasskeyWitness, passkeyWitnesses } from "@mod/passkey-witness";
export * from "./store.ts";
