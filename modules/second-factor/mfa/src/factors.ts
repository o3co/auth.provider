import { type Audit, declaredAudit } from "@mod/audit";
import { isUnavailable, type Log, Unavailable } from "@mod/kernel";
import { isLabel } from "@mod/labels";
import {
	type FactorKind,
	type FirstBindingGate,
	type Opened,
	secondFactorAmr,
} from "@mod/mfa-extensions";
import type { EnrollmentWitness } from "@mod/mfa-witness";
import type { Seal } from "@mod/seal";
import events from "./audit-events.ts";
import type { Factors, Fence, Shown } from "./contract.ts";
import { type Factor, factorRecords, sealContext } from "./records/records.ts";
import type { FactorStore } from "./store.ts";
import { markedBy, standingOf } from "./witness/witness.ts";

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
	/** Who remembers, apart from the store, that a subject enrolled; none composed leaves the store alone to tell. */
	readonly witness: EnrollmentWitness | undefined;
	readonly log: Pick<Log, "warn">;
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
	/** Begun while the subject held no counting factor: it binds only while it would still be the first. */
	readonly first?: true;
	/** The first binding's own mark at the witness, never shown or logged. */
	readonly token?: string;
	/** The subject's fence when it began: a reset or a fence since leaves it nothing to bind. None reads as 0. */
	readonly fences?: number;
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
	const challengeContext = (subject: string, factor: string) =>
		sealContext(subject, `challenge ${factor}`);
	const pendingOf = (subject: string, pending: string) => {
		const value = JSON.parse(opened(pending, sealContext(subject, "pending"))) as Pending;
		const kind = p.kinds.get(value.kind);
		const fences = typeof value.fences === "number" ? value.fences : 0;
		return kind
			? { kind, secret: value.secret, first: value.first === true, token: value.token, fences }
			: undefined;
	};
	const recovery = async (subject: string) => {
		const kind = [...p.kinds.values()].find(isWayBack);
		if (!kind) return undefined;
		const enrolled = await kind.enroll(
			subject,
			heldOf(subject, await records.list(subject), kind.kind),
		);
		// Codes that will not enrol fail as an unanswering store does.
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
	const standing = standingOf(p);
	/** A first binding refused, recorded with why; nothing of it is kept. */
	const closed = (subject: string, kind: string, reason: "competing" | "reset-cleared") => {
		audited.record("mfa.first_binding_conflict", { subject, attributes: { kind, reason } });
		return { kind: "first-binding-closed" } as const;
	};
	/** The factors removed, once more where the store cannot answer the first time. */
	const dropped = async (subject: string, gone: ReadonlySet<string>) => {
		const drop = () =>
			records.decide(subject, (all) => ({
				next: all.filter((f) => !gone.has(f.id)),
				verdict: undefined,
			}));
		await drop().catch((error: unknown) => {
			if (!isUnavailable(error)) throw error;
			return drop();
		});
	};
	// Factors first, then the mark: a failure between leaves a mark and no factor, which stops logins.
	const clear = async (subject: string) => {
		// Written even when nothing is held: the fence moves, so no binding begun before it binds.
		const cleared = await records.decide(subject, (all) => ({
			next: [],
			fence: true,
			verdict: { count: all.length, kinds: [...new Set(all.map((f) => f.kind))].sort() },
		}));
		await p.witness?.clear(subject);
		return cleared;
	};
	return {
		held: async (subject) => usable(await records.list(subject), p.kinds).map(shown),
		countingHeld: async (subject, at) => {
			const counts = counting(await records.list(subject), p.kinds).length > 0;
			return (await standing(subject, counts, at)) === "held";
		},
		secondFactorRequired: () => p.required,
		asks: async (subject) => {
			const all = await records.list(subject);
			const counts = counting(all, p.kinds).length > 0;
			const held = (await standing(subject, counts, "login")) === "held";
			if (p.required && !held) return "binding";
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
			// A past key's secret is sealed again in the write the proof makes anyway.
			const fresh = resealedSecret(subject, factor);
			const written = await records.decide(subject, (all) => {
				const current = all.find((f) => f.id === factor.id);
				if (!current || !sameState(current.state, factor.state)) return { verdict: false };
				const moved = fresh && current.secret === factor.secret ? { secret: fresh } : {};
				const next = all.map((f) =>
					f.id === factor.id ? { ...f, state: result.state, ...moved } : f,
				);
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
			const fences = await records.fences(subject);
			if (all.length >= p.maxFactors) return { kind: "full" };
			const counts = counting(all, p.kinds).length > 0;
			const first = (await standing(subject, counts, "binding")) === "none";
			// A login's ask holds the password alone, which lets it bind a first factor and never add one.
			if (!first && from?.kind === "login") return closed(subject, name, "competing");
			if (p.gates.length > 0 && first) {
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
			const value: Pending = {
				kind: kind.kind,
				secret: enrolled.secret,
				...(first ? { first, token: id() } : {}),
				...(fences > 0 ? { fences } : {}),
			};
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
		bind: async (subject, pending, state, label, from) => {
			if (label !== undefined && !isLabel(label)) return { kind: "malformed-label" };
			const found = pendingOf(subject, pending);
			if (!found) return { kind: "unknown" };
			// A reset or a fence since it began leaves it nothing to bind; checked again in the write below.
			if ((await records.fences(subject)) !== found.fences) return { kind: "fenced" };
			// Asked from a login, it binds only as the first, whenever and however it began.
			const asFirst = found.first || from?.kind === "login";
			// The mark goes first: a first factor never stands unwitnessed, and another binding's mark closes this one.
			const witness = asFirst ? p.witness : undefined;
			if (witness) {
				const owned = found.token !== undefined && (await markedBy(witness, subject, found.token));
				if (!owned) return closed(subject, found.kind.kind, "competing");
			}
			const fid = id();
			const factor: Factor = {
				id: fid,
				kind: found.kind.kind,
				...(label ? { label } : {}),
				secret: p.seal.seal(found.secret, sealContext(subject, fid)),
				state,
				boundAt: p.now(),
			};
			const backed = [...p.kinds.values()].some(isWayBack);
			// Decided on the factors as written: of two first bindings at once, one binds.
			const written = await records.decide<"full" | "closed" | "fenced" | { due: boolean }>(
				subject,
				(all, fences) => {
					if (fences !== found.fences) return { verdict: "fenced" };
					// A first binding another counting factor beat to the subject binds nothing: it was let begin as the first.
					if (asFirst && counting(all, p.kinds).length > 0) return { verdict: "closed" };
					// A subject holding no codes keeps them a place, for the reissue to write them in.
					const due = backed && !all.some(wayBack);
					if (all.length + 1 + (due ? 1 : 0) > p.maxFactors) return { verdict: "full" };
					return { next: [...all, factor], verdict: { due } };
				},
			);
			// Any mark is left: only a reset clears one, as the mark may be a newer binding's by now.
			if (written === "fenced") return { kind: "fenced" };
			if (written === "full") return { kind: "full" };
			if (written === "closed") return closed(subject, factor.kind, "competing");
			const { due } = written;
			const ours = new Set([fid]);
			// A reset that cleared the mark meanwhile cleared this subject: what was written goes too.
			if (witness && !(await witness.read(subject))) {
				await dropped(subject, ours);
				return closed(subject, factor.kind, "reset-cleared");
			}
			const unique = found.kind.uniqueSecret?.({ secret: found.secret, state });
			if (unique !== undefined && !(await records.claim(subject, factor.kind, unique, fid))) {
				// Another factor holds the value: this one goes again.
				await records.decide(subject, (all) => ({
					next: all.filter((f) => !ours.has(f.id)),
					verdict: undefined,
				}));
				return { kind: "duplicate" };
			}
			recorded("factor.enrolled", subject, { kind: factor.kind, factor: fid });
			return { kind: "bound", factor: shown(factor), fence: found.fences as Fence, codesDue: due };
		},
		fence: (subject) => records.fence(subject),
		fenceOf: async (subject) => (await records.fences(subject)) as Fence,
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
		remove: async (subject, target, fence) => {
			const removed = await records.decide<"unknown" | "last" | "fenced" | { kind: string }>(
				subject,
				(all, fences) => {
					if (fences !== fence) return { verdict: "fenced" };
					const kind = all.find((f) => f.id === target)?.kind;
					if (kind === undefined) return { verdict: "unknown" };
					const rest = all.filter((f) => f.id !== target);
					const counted = counting(rest, p.kinds).length > 0;
					// Under a witness only a reset ends an enrollment: its mark stays, so no factor would stand for it.
					if ((p.required || p.witness) && !counted) return { verdict: "last" };
					// A way back left alone would hold every login once its codes run out: it goes with the last counting factor.
					return { next: counted ? rest : rest.filter((f) => !wayBack(f)), verdict: { kind } };
				},
			);
			if (typeof removed === "string") return removed;
			recorded("factor.removed", subject, { kind: removed.kind, factor: target });
			return "removed";
		},
		clear,
		reissue: async (subject, fence) => {
			const codes = await recovery(subject);
			// Decided on the factors as written: no codes land beside no counting factor, and the old set goes in the same write.
			const written = await records.decide<
				"fenced" | "no-qualifying-factor" | "full" | { replaced: boolean }
			>(subject, (all, fences) => {
				if (fences !== fence) return { verdict: "fenced" };
				if (counting(all, p.kinds).length === 0) return { verdict: "no-qualifying-factor" };
				if (!codes) return { verdict: { replaced: false } };
				const replaced = all.some((f) => f.kind === codes.factor.kind);
				// A first set takes the place its binding kept, unless another factor took it meanwhile.
				if (!replaced && all.length + 1 > p.maxFactors) return { verdict: "full" };
				const next = [...all.filter((f) => f.kind !== codes.factor.kind), codes.factor];
				return { next, verdict: { replaced } };
			});
			if (typeof written === "string") return { kind: written };
			if (!codes) return { kind: "unknown-kind" };
			recorded("recovery_codes.generated", subject, {
				kind: codes.factor.kind,
				regenerated: String(written.replaced),
			});
			return { kind: "reissued", codes: codes.show };
		},
	};
}
