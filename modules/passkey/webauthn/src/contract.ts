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
	/** How long a challenge can be answered after it was made: the relying party's `challenge-lifetime`, in ms. */
	readonly lifetimeMs: number;
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
	/** Options for an assertion by one of `allow`, and the challenge to keep for its answer: it carries whether `allow` named any, so `assert` asks for the user handle where none was named. */
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

export { challengeOf } from "./ceremony/ceremony.ts";
export { credentialLimits, credentialOf, freshHandle, isCanonical } from "./records.ts";
