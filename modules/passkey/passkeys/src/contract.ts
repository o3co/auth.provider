import { contract } from "@mod/kernel";
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
	| "full";

/** Passkeys for a subject the caller vouches for, each answering a challenge made for it, once. Throws Unavailable when the store cannot tell. */
export interface Registrations {
	/** Options for a new passkey of `subject`, excluding its own; its first options make its user handle. */
	creation(subject: string): Promise<{ readonly options: unknown }>;
	register(
		subject: string,
		response: unknown,
		nickname?: string,
	): Promise<
		| { readonly kind: "registered"; readonly credential: Credential }
		| { readonly kind: "refused"; readonly reason: RegistrationRefusal }
	>;
}

export const registrations = contract<Registrations>("passkeys.registrations");

export * from "./store.ts";
