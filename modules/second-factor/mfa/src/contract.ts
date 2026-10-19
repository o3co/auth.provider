import { contract, extensionPoint } from "@mod/kernel";
import type { AskedFrom, RefusedReason } from "@mod/mfa-extensions";
import type { AuthContext } from "@mod/session";

/** A step where a user proves a factor at login; without one, a factor could never be proven. */
export interface ProofStep {
	readonly name: string;
}

/** The steps that prove factors. mfa refuses to start without at least one. */
export const proofSteps = extensionPoint<ProofStep>("mfa.proof-steps", { multiplicity: "some" });

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
	/** Whether the session proved a second factor recently, by `recent`; a recent sign-in never stands for one, whatever the subject holds. */
	provenRecently(context: AuthContext): boolean;
	/** Sends the factor's challenge, good at most until `until` (epoch ms on kernel's clock). */
	challenge(subject: string, factor: string, until: number, from?: AskedFrom): Promise<Challenged>;
	/** Judges a proof, given the sealed challenge kept; the next state is kept only over the state judged. */
	prove(subject: string, factor: string, proof: string, challenge?: string): Promise<Proved>;
	/** New secret material of a counting kind, sealed for the subject, and what to show once; `passed` and `transaction` go to the gates unread. Asked from a login, it begins only the subject's first counting factor. */
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
					| "binding-proof-required"
					| "first-binding-closed";
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
	/** Binds a proved binding; recovery codes come with the first counting factor, once. One begun as the first counting factor, or asked from a login, binds only while no other counts by then (`first-binding-closed`). The caller passes `from` as it passed it to `begin`. */
	bind(
		subject: string,
		pending: string,
		state: unknown,
		label?: string,
		from?: AskedFrom,
	): Promise<
		| {
				readonly kind: "bound";
				readonly factor: Shown;
				readonly recoveryCodes?: unknown;
				/** The codes' own factor, so a caller that cannot show them can take them back with `remove`. */
				readonly recoveryCodesFactor?: string;
		  }
		| {
				readonly kind:
					| "full"
					| "unknown"
					| "malformed-label"
					| "duplicate"
					| "first-binding-closed";
		  }
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
