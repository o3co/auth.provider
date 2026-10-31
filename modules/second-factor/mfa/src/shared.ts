import { type Audit, declaredAudit } from "@mod/audit";
import { type Log, Unavailable } from "@mod/kernel";
import type { FactorKind, FirstBindingGate, Opened, Witnessing } from "@mod/mfa-extensions";
import { issuedWayBack, secondFactorAmr } from "@mod/mfa-extensions";
import type { Shown } from "@mod/mfa-reading";
import type { Seal } from "@mod/seal";
import events from "./audit-events.ts";
import { type Factor, factorRecords, sealContext } from "./records/records.ts";
import type { FactorStore } from "./store.ts";

export interface FactorParts {
	readonly stored: FactorStore;
	readonly kinds: ReadonlyMap<string, FactorKind>;
	readonly seal: Seal;
	readonly required: boolean;
	readonly maxFactors: number;
	readonly gates: readonly FirstBindingGate[];
	readonly random: (n: number) => Uint8Array;
	readonly now: () => number;
	readonly audit: Audit;
	/** Who tells, apart from the store, that a subject enrolled; none leaves the store alone to tell. */
	readonly witnessing: Witnessing | undefined;
	readonly log: Pick<Log, "warn">;
}

export const byKind = (kinds: readonly FactorKind[]) => new Map(kinds.map((k) => [k.kind, k]));
export const addsMfa = (kind: FactorKind) => kind.addsSecondFactor;
/** Whether guessing can beat the kind: unless it says no, as 0.17 took it, so a kind that says nothing is held to the stricter side. */
export const guessing = (kind: FactorKind) => kind.guessable !== false;
/** A proof's own amr kept to its kind's, else its kind's, and `mfa` when the kind adds it. */
export const amrOf = (kind: FactorKind, own?: readonly string[]) => [
	...(own ? own.filter((amr) => kind.amr.includes(amr)) : kind.amr),
	...(addsMfa(kind) ? [secondFactorAmr] : []),
];
/** The factors the subject holds of kinds this deployment knows. */
export const usable = (all: readonly Factor[], kinds: ReadonlyMap<string, FactorKind>) =>
	all.filter((f) => kinds.has(f.kind));
export const counting = (all: readonly Factor[], kinds: ReadonlyMap<string, FactorKind>) =>
	all.filter((f) => kinds.get(f.kind)?.counts);
export const shown = (factor: Factor): Shown => ({
	id: factor.id,
	kind: factor.kind,
	...(factor.label ? { label: factor.label } : {}),
});
/** States are JSON as the store keeps them, so equal text means the same state. */
export const sameState = (a: unknown, b: unknown) =>
	JSON.stringify(a ?? null) === JSON.stringify(b ?? null);

/** What every part of the decisions works with: the parts, the records, the audit, and the secrets opened. */
export function sharedOf(p: FactorParts) {
	const wayBack = (factor: Factor) => {
		const kind = p.kinds.get(factor.kind);
		return kind !== undefined && issuedWayBack(kind);
	};
	const records = factorRecords(p.stored);
	const audited = declaredAudit(p.audit, events);
	const recorded = (
		kind: "factor.enrolled" | "factor.removed" | "recovery_code.used" | "recovery_codes.generated",
		subject: string,
		attributes: Record<string, string>,
	) => audited.record(`mfa.${kind}`, { subject, attributes });
	const id = () => Buffer.from(p.random(16)).toString("base64url");
	const opened = (sealed: string, context: string) => {
		const plain = p.seal.open(sealed, context);
		if (plain.kind !== "opened") throw new Unavailable("mfa");
		return plain.plain;
	};
	const secretOf = (subject: string, factor: Factor) =>
		opened(factor.secret, sealContext(subject, factor.id));
	/** The secret sealed again under the current key when a past key sealed it; none otherwise. */
	const resealedSecret = (subject: string, factor: Factor) => {
		const read = p.seal.open(factor.secret, sealContext(subject, factor.id));
		return read.kind === "opened" && read.stale
			? p.seal.seal(read.plain, sealContext(subject, factor.id))
			: undefined;
	};
	const heldOf = (subject: string, all: readonly Factor[], kind: string): Opened[] =>
		all
			.filter((f) => f.kind === kind)
			.map((f) => ({ secret: secretOf(subject, f), state: f.state }));
	return {
		p,
		wayBack,
		records,
		audited,
		recorded,
		id,
		opened,
		secretOf,
		resealedSecret,
		heldOf,
	};
}

export type Shared = ReturnType<typeof sharedOf>;
