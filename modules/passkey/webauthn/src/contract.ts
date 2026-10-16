import { contract } from "@mod/kernel";

/** WebAuthn's user verification requirement; only `required` refuses a response without it. */
export type Verification = "required" | "preferred" | "discouraged";

/** A credential to check assertions with; ids, keys and handles are unpadded base64url. Its holder may keep it. */
export interface Credential {
	readonly id: string;
	readonly publicKey: string;
	readonly signCount: number;
	readonly userHandle: string;
	readonly backupEligible: boolean;
	readonly backedUp: boolean;
	readonly transports?: readonly string[];
}

export type CeremonyRefusal =
	| "malformed"
	| "challenge"
	| "origin"
	| "top-origin"
	| "rp"
	| "algorithm"
	| "signature"
	| "sign-count"
	| "user-handle"
	| "user-verification"
	| "backup-eligibility";

export type Asserted =
	/** `credential` carries the new sign count and backup state, for the holder to keep. */
	| { readonly kind: "asserted"; readonly credential: Credential; readonly userVerified: boolean }
	| { readonly kind: "refused"; readonly reason: CeremonyRefusal };

/** Ceremonies whose challenge, its end (`until`, on `kernel`'s clock) and credential the caller keeps and hands over once. */
export interface Ceremonies {
	/** Options for a new credential, and the challenge to keep for its answer; a discoverable one unless told otherwise. */
	creation(
		user: { readonly handle: string; readonly name: string },
		exclude: readonly string[],
		v: Verification,
		asked?: { readonly discoverable?: boolean },
	): { readonly options: unknown; readonly challenge: string; readonly until: number };
	attest(
		response: unknown,
		challenge: string,
		handle: string,
		v: Verification,
		until?: number,
	): Promise<
		| { readonly kind: "attested"; readonly credential: Credential }
		| { readonly kind: "refused"; readonly reason: CeremonyRefusal }
	>;
	/** Options for an assertion by one of `allow`, and the challenge to keep for its answer. */
	request(
		allow: readonly Credential[],
		v: Verification,
	): { readonly options: unknown; readonly challenge: string; readonly until: number };
	assert(
		response: unknown,
		challenge: string,
		credential: Credential,
		v: Verification,
		until?: number,
	): Promise<Asserted>;
}

export const ceremonies = contract<Ceremonies>("webauthn.ceremonies");

/** Assertions by the discoverable passkeys webauthn keeps. Throws Unavailable when the store cannot tell. */
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

export const passkeys = contract<Passkeys>("webauthn.passkeys");

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

export const registrations = contract<Registrations>("webauthn.registrations");

export { credentialOf, freshHandle } from "./records.ts";
export * from "./store.ts";
