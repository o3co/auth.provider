import { type Audit, declaredAudit } from "@mod/audit";
import { Unavailable } from "@mod/kernel";
import type { Seal } from "@mod/seal";
import events from "./audit-events.ts";
import {
	type FactorKind,
	type Factors,
	type FirstBindingGate,
	isLabel,
	type Opened,
	type Shown,
	secondFactorAmr,
} from "./contract.ts";
import { type Factor, factorRecords, sealContext } from "./records.ts";
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
	readonly recentMs: number;
	readonly audit: Audit;
}

export const byKind = (kinds: readonly FactorKind[]) => new Map(kinds.map((k) => [k.kind, k]));
export const addsMfa = (kind: FactorKind) => kind.addsSecondFactor;
/** Whether guessing can beat the kind: unless it says no, as 0.17 took it, so a kind that says nothing is held to the stricter side. */
export const guessing = (kind: FactorKind) => kind.guessable !== false;
/** A proof's own amr kept to its kind's, else its kind's, and `mfa` when the kind adds it. */
const amrOf = (kind: FactorKind, own?: readonly string[]) => [
	...(own ? own.filter((amr) => kind.amr.includes(amr)) : kind.amr),
	...(addsMfa(kind) ? [secondFactorAmr] : []),
];
/** The factors the subject holds of kinds this deployment knows. */
const usable = (all: readonly Factor[], kinds: ReadonlyMap<string, FactorKind>) =>
	all.filter((f) => kinds.has(f.kind));
export const counting = (all: readonly Factor[], kinds: ReadonlyMap<string, FactorKind>) =>
	all.filter((f) => kinds.get(f.kind)?.counts);
const shown = (factor: Factor): Shown => ({
	id: factor.id,
	kind: factor.kind,
	...(factor.label ? { label: factor.label } : {}),
});
/** States are JSON as the store keeps them, so equal text means the same state. */
const sameState = (a: unknown, b: unknown) =>
	JSON.stringify(a ?? null) === JSON.stringify(b ?? null);

/** A binding begun: the kind and its secret, sealed together for the subject. */
interface Pending {
	readonly kind: string;
	readonly secret: string;
}

const isWayBack = (kind: FactorKind) => !kind.counts && !guessing(kind);

export function factorDecisions(p: FactorParts): Factors {
	const wayBack = (factor: Factor) => {
		const kind = p.kinds.get(factor.kind);
		return kind !== undefined && isWayBack(kind);
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
	const heldOf = (subject: string, all: readonly Factor[], kind: string): Opened[] =>
		all
			.filter((f) => f.kind === kind)
			.map((f) => ({ secret: secretOf(subject, f), state: f.state }));
	const challengeContext = (subject: string, factor: string) =>
		sealContext(subject, `challenge ${factor}`);
	const pendingOf = (subject: string, pending: string) => {
		const value = JSON.parse(opened(pending, sealContext(subject, "pending"))) as Pending;
		const kind = p.kinds.get(value.kind);
		return kind ? { kind, secret: value.secret } : undefined;
	};
	const recovery = async (subject: string) => {
		const kind = [...p.kinds.values()].find(isWayBack);
		if (!kind) return undefined;
		const enrolled = await kind.enroll(
			subject,
			heldOf(subject, await records.list(subject), kind.kind),
		);
		// Without its way back a first binding cannot finish, so it fails as an unanswering store does.
		if (!("secret" in enrolled)) throw new Unavailable("mfa");
		const fid = id();
		const factor: Factor = {
			id: fid,
			kind: kind.kind,
			secret: p.seal.seal(enrolled.secret, sealContext(subject, fid)),
			state: null,
			boundAt: p.now(),
		};
		return { factor, show: enrolled.show };
	};
	const clear = (subject: string) =>
		records.decide(subject, (all) => ({
			next: all.length > 0 ? [] : undefined,
			verdict: { count: all.length, kinds: [...new Set(all.map((f) => f.kind))].sort() },
		}));
	return {
		held: async (subject) => usable(await records.list(subject), p.kinds).map(shown),
		countingHeld: async (subject) => counting(await records.list(subject), p.kinds).length > 0,
		asks: async (subject) => {
			const all = await records.list(subject);
			if (p.required && counting(all, p.kinds).length === 0) return "binding";
			return usable(all, p.kinds).length === 0 ? "nothing" : "proof";
		},
		guessable: async (subject, factor) => {
			const found = (await records.list(subject)).find((f) => f.id === factor);
			const kind = found && p.kinds.get(found.kind);
			return kind && guessing(kind);
		},
		guessableBoundAfter: async (subject, after) =>
			(await records.list(subject)).every((f) => {
				const kind = p.kinds.get(f.kind);
				if (kind === undefined) return false;
				return !guessing(kind) || (f.boundAt !== undefined && f.boundAt > after);
			}),
		recent: (at) => p.now() - at <= p.recentMs,
		challenge: async (subject, target, until, from) => {
			const factor = (await records.list(subject)).find((f) => f.id === target);
			const kind = factor && p.kinds.get(factor.kind);
			if (!factor || !kind) return { kind: "unknown" };
			if (!kind.challenge) return { kind: "none" };
			const [held] = heldOf(subject, [factor], factor.kind);
			const sent = await kind.challenge(subject, held as Opened, until, from);
			if (sent.kind === "limited") return sent;
			if (sent.kind === "refused") {
				const why = sent.reason ? { reason: sent.reason } : {};
				return { kind: "refused", factorKind: kind.kind, ...why };
			}
			const sealed = p.seal.seal(sent.kept, challengeContext(subject, factor.id));
			return { kind: "sent", factorKind: kind.kind, show: sent.show, sealed };
		},
		prove: async (subject, target, proof, challenge) => {
			const factor = (await records.list(subject)).find((f) => f.id === target);
			const kind = factor && p.kinds.get(factor.kind);
			// The caller found it through `guessable` first: gone now means it went meanwhile.
			if (!factor || !kind) return { kind: "raced" };
			const secret = secretOf(subject, factor);
			const kept =
				challenge === undefined
					? undefined
					: opened(challenge, challengeContext(subject, factor.id));
			const result = await kind.verify(secret, factor.state, proof, kept);
			if (result.kind !== "valid") return result;
			const written = await records.decide(subject, (all) => {
				const current = all.find((f) => f.id === factor.id);
				if (!current || !sameState(current.state, factor.state)) return { verdict: false };
				const next = all.map((f) => (f.id === factor.id ? { ...f, state: result.state } : f));
				return { next, verdict: true };
			});
			if (!written) return { kind: "raced" };
			if (isWayBack(kind)) {
				const remaining =
					result.remaining === undefined ? {} : { remaining: String(result.remaining) };
				recorded("recovery_code.used", subject, {
					kind: kind.kind,
					factor: factor.id,
					...remaining,
				});
			}
			return { kind: "valid", amr: amrOf(kind, result.amr) };
		},
		begin: async (subject, name, passed, transaction, from) => {
			const kind = p.kinds.get(name);
			if (!kind?.counts) return { kind: "unknown-kind" };
			const all = await records.list(subject);
			if (all.length >= p.maxFactors) return { kind: "full" };
			if (p.gates.length > 0 && counting(all, p.kinds).length === 0) {
				const ask = { subject, kind: name, transaction, passed, from };
				for (const gate of p.gates) {
					if (!(await gate.admits(ask))) return { kind: "binding-proof-required" };
				}
			}
			const enrolled = await kind.enroll(subject, heldOf(subject, all, kind.kind), from);
			if (!("secret" in enrolled)) return { kind: enrolled.kind };
			const unique = kind.uniqueSecret?.({ secret: enrolled.secret, state: null });
			if (unique !== undefined && (await records.taken(kind.kind, unique))) {
				return { kind: "duplicate" };
			}
			const value: Pending = { kind: kind.kind, secret: enrolled.secret };
			const pending = p.seal.seal(JSON.stringify(value), sealContext(subject, "pending"));
			return { kind: "begun", pending, show: enrolled.show };
		},
		provePending: async (subject, pending, proof) => {
			const found = pendingOf(subject, pending);
			if (!found) return { kind: "unknown" };
			const result = await found.kind.verify(found.secret, null, proof);
			if (result.kind !== "valid") return { kind: "invalid" };
			return { kind: "valid", state: result.state, amr: amrOf(found.kind, result.amr) };
		},
		bind: async (subject, pending, state, label) => {
			if (label !== undefined && !isLabel(label)) return { kind: "malformed-label" };
			const found = pendingOf(subject, pending);
			if (!found) return { kind: "unknown" };
			const fid = id();
			const factor: Factor = {
				id: fid,
				kind: found.kind.kind,
				...(label ? { label } : {}),
				secret: p.seal.seal(found.secret, sealContext(subject, fid)),
				state,
				boundAt: p.now(),
			};
			// Made before the write, which must be pure; dropped when the subject already holds codes.
			const codes = await recovery(subject);
			// Decided on the factors as written: of two first bindings at once, one brings the codes.
			const written = await records.decide<"full" | { brought: typeof codes }>(subject, (all) => {
				const brought = codes && !all.some((f) => f.kind === codes.factor.kind) ? codes : undefined;
				const added = [factor, ...(brought ? [brought.factor] : [])];
				if (all.length + added.length > p.maxFactors) return { verdict: "full" };
				return { next: [...all, ...added], verdict: { brought } };
			});
			if (written === "full") return { kind: "full" };
			const { brought } = written;
			const unique = found.kind.uniqueSecret?.({ secret: found.secret, state });
			if (unique !== undefined && !(await records.claim(subject, factor.kind, unique, fid))) {
				// Another factor holds the value: this one goes again, with the codes it brought.
				const gone = new Set([fid, ...(brought ? [brought.factor.id] : [])]);
				await records.decide(subject, (all) => ({
					next: all.filter((f) => !gone.has(f.id)),
					verdict: undefined,
				}));
				return { kind: "duplicate" };
			}
			recorded("factor.enrolled", subject, { kind: factor.kind, factor: fid });
			if (brought) {
				recorded("recovery_codes.generated", subject, {
					kind: brought.factor.kind,
					regenerated: "false",
				});
			}
			return {
				kind: "bound",
				factor: shown(factor),
				...(brought ? { recoveryCodes: brought.show } : {}),
			};
		},
		rename: async (subject, target, label) => {
			if (!isLabel(label)) return "malformed-label";
			return records.decide(subject, (all) =>
				all.some((f) => f.id === target)
					? {
							next: all.map((f) => (f.id === target ? { ...f, label } : f)),
							verdict: "renamed" as const,
						}
					: { verdict: "unknown" as const },
			);
		},
		remove: async (subject, target) => {
			const removed = await records.decide<"unknown" | "last" | { kind: string }>(
				subject,
				(all) => {
					const kind = all.find((f) => f.id === target)?.kind;
					if (kind === undefined) return { verdict: "unknown" };
					const rest = all.filter((f) => f.id !== target);
					const counted = counting(rest, p.kinds).length > 0;
					if (p.required && !counted) return { verdict: "last" };
					// A way back left alone would hold every login once its codes run out: it goes with the last counting factor.
					return { next: counted ? rest : rest.filter((f) => !wayBack(f)), verdict: { kind } };
				},
			);
			if (typeof removed === "string") return removed;
			recorded("factor.removed", subject, { kind: removed.kind, factor: target });
			return "removed";
		},
		clear,
		reissue: async (subject) => {
			const codes = await recovery(subject);
			// Decided on the factors as written: no codes land beside no counting factor, and the old set goes in the same write.
			const counted = await records.decide(subject, (all) => {
				const holds = counting(all, p.kinds).length > 0;
				const next =
					holds && codes
						? [...all.filter((f) => f.kind !== codes.factor.kind), codes.factor]
						: undefined;
				return { next, verdict: holds };
			});
			if (!counted) return { kind: "no-qualifying-factor" };
			if (!codes) return { kind: "unknown-kind" };
			recorded("recovery_codes.generated", subject, {
				kind: codes.factor.kind,
				regenerated: "true",
			});
			return { kind: "reissued", codes: codes.show };
		},
	};
}
