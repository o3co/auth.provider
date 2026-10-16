import { contract, extensionPoint } from "@mod/kernel";
import type { AskedFrom, Sending } from "@mod/mfa";

/** A proof asked of a subject before a first counting factor, such as owning a contact. */
export interface BindingProof {
	readonly name: string;
	available(subject: string, from?: AskedFrom): Promise<boolean>;
	/** Sends its challenge, good at most until `until` (epoch ms on kernel's clock). */
	send(subject: string, until: number, from?: AskedFrom): Promise<Sending>;
	/** Whether `proof` answers what the challenge kept. */
	check(subject: string, kept: string, proof: string): Promise<boolean>;
}

export const bindingProofs = extensionPoint<BindingProof>("mfa-binding-proof.proofs", {
	multiplicity: "keyed",
	keyOf: (proof) => proof.name,
});

export type BindingChallenged =
	| {
			readonly kind: "sent";
			readonly proof: string;
			readonly show: object;
			readonly sealed: string;
	  }
	/** No proof is asked before this subject's first binding. */
	| { readonly kind: "none" }
	| { readonly kind: "limited" }
	| { readonly kind: "refused"; readonly proof: string };

/** The one transaction, and the kind, a pass begins a binding for. */
export interface PassBound {
	readonly transaction: string;
	readonly kind: string;
}

export interface BindingProofs {
	/** Whether a first counting factor waits for the proof, sending nothing. */
	asks(subject: string, from?: AskedFrom): Promise<"proof" | "nothing">;
	/** Sends the proof asked, good at most until `until`. */
	challenge(subject: string, until: number, from?: AskedFrom): Promise<BindingChallenged>;
	/** When `answer` answers the sealed challenge, in time: the pass mfa's `begin` takes, sealed to the subject and `bound`. */
	prove(
		subject: string,
		answer: string,
		challenge: string,
		bound: PassBound,
	): Promise<string | undefined>;
}

export const bindingProof = contract<BindingProofs>("mfa-binding-proof");
