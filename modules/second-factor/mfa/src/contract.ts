import { contract, extensionPoint } from "@mod/kernel";

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

/** A step where a user proves a factor at login; without one, a factor could never be proven. */
export interface ProofStep {
	readonly name: string;
}

/** The steps that prove factors. mfa refuses to start without at least one. */
export const proofSteps = extensionPoint<ProofStep>("mfa.proof-steps", { multiplicity: "some" });

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

/** A factor as the user sees it. */
export interface Shown {
	readonly id: string;
	readonly kind: string;
	readonly label?: string;
}

/** Controls and line separators break a line; directional marks and bidi controls reorder text. */
const unshowable = /[\p{Cc}\u061c\u200e\u200f\u2028-\u202e\u2066-\u2069]/u;

/** Whether a page can show `text` as a factor's label: 1 to 64 code points, well formed. */
export const isLabel = (text: string): boolean =>
	text.length > 0 && [...text].length <= 64 && text.isWellFormed() && !unshowable.test(text);

export type Proved =
	/** `amr` is what this proof adds. */
	| { readonly kind: "valid"; readonly amr: readonly string[] }
	| { readonly kind: "invalid" }
	| { readonly kind: "replayed" }
	/** Right, but the factor changed or went while it was judged: it counts for nothing. */
	| { readonly kind: "raced" };

export type Challenged =
	/** `show` goes to the user unread; `sealed` is kept for the factor's next proof. */
	| {
			readonly kind: "sent";
			readonly factorKind: string;
			readonly show: object;
			readonly sealed: string;
	  }
	/** The factor's kind sends no challenge. */
	| { readonly kind: "none" }
	| { readonly kind: "limited" }
	| { readonly kind: "refused"; readonly factorKind: string; readonly reason?: RefusedReason }
	| { readonly kind: "unknown" };

/** Decisions on the subject's factors, whose records and secrets stay with mfa; a binding takes three calls, so the caller can settle its own records in between. */
export interface Factors {
	/** The factors of kinds this deployment knows. */
	held(subject: string): Promise<readonly Shown[]>;
	/** Whether the subject holds a counting factor. */
	countingHeld(subject: string): Promise<boolean>;
	/** What a login asks of the subject: nothing, a proof of a factor, or a first binding. */
	asks(subject: string): Promise<"nothing" | "proof" | "binding">;
	/** Whether guessing can beat this factor; nothing when the subject holds no such factor. */
	guessable(subject: string, factor: string): Promise<boolean | undefined>;
	/** Whether every factor of a guessable kind the subject holds was bound after `after` (epoch ms, kernel's clock); true when it holds none. */
	guessableBoundAfter(subject: string, after: number): Promise<boolean>;
	/** Whether a proof at `at` (epoch ms, kernel's clock) is still recent, by `session`'s one window. */
	recent(at: number): boolean;
	/** Sends the factor's challenge, good at most until `until` (epoch ms on kernel's clock). */
	challenge(subject: string, factor: string, until: number, from?: AskedFrom): Promise<Challenged>;
	/** Judges a proof, given the sealed challenge kept; the next state is kept only over the state judged. */
	prove(subject: string, factor: string, proof: string, challenge?: string): Promise<Proved>;
	/** New secret material of a counting kind, sealed for the subject, and what to show once; `passed` and `transaction` go to the gates unread. */
	begin(
		subject: string,
		kind: string,
		passed?: string,
		transaction?: string,
		from?: AskedFrom,
	): Promise<
		| { readonly kind: "begun"; readonly pending: string; readonly show: object }
		| {
				readonly kind:
					| "unknown-kind"
					| "full"
					| "limited"
					| "refused"
					| "duplicate"
					| "binding-proof-required";
		  }
	>;
	/** Judges the first proof of a binding begun; `amr` is what this proof adds, as `prove` answers it. */
	provePending(
		subject: string,
		pending: string,
		proof: string,
	): Promise<
		| { readonly kind: "valid"; readonly state: unknown; readonly amr: readonly string[] }
		| { readonly kind: "invalid" | "unknown" }
	>;
	/** Binds a proved binding; recovery codes come with the first counting factor, once. */
	bind(
		subject: string,
		pending: string,
		state: unknown,
		label?: string,
	): Promise<
		| {
				readonly kind: "bound";
				readonly factor: Shown;
				readonly recoveryCodes?: unknown;
		  }
		| { readonly kind: "full" | "unknown" | "malformed-label" | "duplicate" }
	>;
	rename(
		subject: string,
		factor: string,
		label: string,
	): Promise<"renamed" | "unknown" | "malformed-label">;
	/** Under required mode, the last counting factor is not removed. */
	remove(subject: string, factor: string): Promise<"removed" | "unknown" | "last">;
	/** Removes every factor of the subject, of any kind, and answers how many and of which kinds; nothing is recorded. */
	clear(subject: string): Promise<{ readonly count: number; readonly kinds: readonly string[] }>;
	/** Replaces the recovery codes, for a subject holding a counting factor. */
	reissue(
		subject: string,
	): Promise<
		| { readonly kind: "reissued"; readonly codes: unknown }
		| { readonly kind: "no-qualifying-factor" | "unknown-kind" }
	>;
}

export const factors = contract<Factors>("mfa.factors");

export * from "./store.ts";
