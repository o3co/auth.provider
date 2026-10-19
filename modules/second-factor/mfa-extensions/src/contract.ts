import { extensionPoint } from "@mod/kernel";

export type Verified =
	/**
	 * `state` is kept with the factor and given to the next verification; `amr` is this proof's,
	 * among its kind's; `remaining` is how many proofs a way back has left, recorded with its use.
	 */
	| {
			readonly kind: "valid";
			readonly state: unknown;
			readonly amr?: readonly string[];
			readonly remaining?: number;
	  }
	| { readonly kind: "invalid" }
	/** A proof already used, or older than one used. */
	| { readonly kind: "replayed" };

/** The amr a proof adds when its kind adds a second factor (RFC 8176). */
export const secondFactorAmr = "mfa";

/** A factor as its kind reads it: the secret opened, and the state. */
export interface Opened {
	readonly secret: string;
	readonly state: unknown;
}

export type Sending =
	/** `show` goes to the user; `kept` comes back with the proof, sealed by mfa meanwhile. */
	| { readonly kind: "sent"; readonly show: object; readonly kept: string }
	| { readonly kind: "limited" }
	/** It will not send to the factor as it stands; `contact-changed` when the contact it was bound to is no longer the subject's. */
	| { readonly kind: "refused"; readonly reason?: RefusedReason };

export type RefusedReason = "contact-changed";

/** Where an ask came from, passed to kinds and binding proofs unread: a login with the email it stated, or a session. */
export type AskedFrom =
	| { readonly kind: "login"; readonly email?: string; readonly vouched?: true }
	| { readonly kind: "session"; readonly handle: string };

/** What a kind's enrolment gives: new secret material and what to show once, or why it gives none. */
export type Enrolled =
	| { readonly secret: string; readonly show: object }
	| { readonly kind: "limited" }
	| { readonly kind: "refused" }
	/** The subject already holds a factor of this kind for the same thing, as the kind tells. */
	| { readonly kind: "duplicate" };

/** A kind of second factor, contributed by the module that owns it. */
export interface FactorKind {
	readonly kind: string;
	/** The amr values a proof of this kind can add, `mfa` aside. */
	readonly amr: readonly string[];
	/** Whether a proof of this kind adds `mfa`. */
	readonly addsSecondFactor: boolean;
	/** Whether guessing can beat it, so failures count toward a lockout. */
	readonly guessable: boolean;
	/** Whether it meets a required second factor; one that does not is a way back only. */
	readonly counts: boolean;
	/** The value no two factors of this kind may hold, whatever their subjects; none while it cannot be told. */
	uniqueSecret?(factor: Opened): string | undefined;
	/** New secret material, sealed by mfa, and what to show once; `held` is the subject's factors of this kind. */
	enroll(subject: string, held: readonly Opened[], from?: AskedFrom): Promise<Enrolled>;
	/** Sends a challenge for the factor, good at most until `until` (epoch ms on kernel's clock). */
	challenge?(subject: string, factor: Opened, until: number, from?: AskedFrom): Promise<Sending>;
	/** `kept` is what the factor's last challenge kept, when one was sent. */
	verify(secret: string, state: unknown, proof: string, kept?: string): Promise<Verified>;
}

export const factorKinds = extensionPoint<FactorKind>("mfa.factor-kinds", {
	multiplicity: "keyed",
	keyOf: (kind) => kind.kind,
});

/** What `begin` asks a gate before a subject's first counting factor: what the caller gave, unread. */
export interface FirstBindingAsk {
	readonly subject: string;
	readonly kind: string;
	readonly transaction: string | undefined;
	readonly passed: string | undefined;
	readonly from: AskedFrom | undefined;
}

/** Whether a first counting factor may begin; a gate refusing answers `binding-proof-required`. */
export interface FirstBindingGate {
	admits(ask: FirstBindingAsk): Promise<boolean>;
}

export const firstBindingGates = extensionPoint<FirstBindingGate>("mfa.first-binding-gates", {
	multiplicity: "many",
});
