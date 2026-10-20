import type { FlowTransactions, Transaction } from "@mod/mfa-flows";

/** A binding proof's challenge: the proof's name, and what mfa-binding-proof sealed. */
export interface BindingChallenge {
	readonly proof: string;
	readonly sealed: string;
}

/** What a binding keeps in its transaction (the card says what each part is). */
export interface Binding {
	readonly pending?: string;
	readonly bindingChallenge?: BindingChallenge;
	readonly bindingPassed?: { readonly kind: string; readonly pass: string };
	readonly proved?: true;
}

/** What a transaction holds for its binding; none held is an empty one. */
export const heldOf = (t: Pick<Transaction, "held"> | undefined): Binding =>
	(t?.held ?? {}) as Binding;

/** A binding's changes to its transaction, each from what it holds; false when it is no longer in use. */
export const holding = (transactions: Pick<FlowTransactions, "keep">) => {
	const keep = async (id: string, change: (held: Binding) => Binding | undefined) =>
		(await transactions.keep(id, (held) => change((held ?? {}) as Binding))) !== undefined;
	return {
		/** Holds a binding begun in the transaction, ending the pass it began with. */
		hold: (id: string, pending: string) =>
			keep(id, ({ bindingPassed: _, ...held }) => ({ ...held, pending })),
		/** Holds the binding proof's challenge sent. */
		bindingSent: (id: string, bindingChallenge: BindingChallenge) =>
			keep(id, (held) => ({ ...held, bindingChallenge })),
		/** Keeps the binding proof's pass, only while the challenge it answered is the one held. */
		bindingPassed: (id: string, sealed: string, passed: { kind: string; pass: string }) =>
			keep(id, ({ bindingChallenge, ...held }) =>
				bindingChallenge?.sealed === sealed
					? { ...held, bindingPassed: passed, proved: true }
					: undefined,
			),
	};
};
