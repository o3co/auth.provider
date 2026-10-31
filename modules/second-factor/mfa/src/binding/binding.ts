import { isLabel } from "@mod/labels";
import type { FactorBinding } from "@mod/mfa-binding";
import { issuedWayBack } from "@mod/mfa-extensions";
import type { Fence } from "@mod/mfa-reading";
import type { Clearing } from "../clearing/clearing.ts";
import { type Decision, type Factor, sealContext } from "../records/records.ts";
import { amrOf, counting, type Shared, shown } from "../shared.ts";
import type { Standing } from "../standing/standing.ts";

/** A binding begun: the kind and its secret, sealed together for the subject. */
interface Pending {
	readonly kind: string;
	readonly secret: string;
	/** Begun while the subject held no counting factor: it binds only while it would still be the first. */
	readonly first?: true;
	/** The subject's fence when it began: a reset or a fence since leaves it nothing to bind. None reads as 0. */
	readonly fences?: number;
}

/** A factor begun, proved and bound: the binding's three steps, a first binding held to being the first. */
export function bindingWith(
	{ p, records, recorded, id, opened, heldOf, wayBack }: Shared,
	{ standing }: Standing,
	{ settle, closed }: Clearing,
): Pick<FactorBinding, "begin" | "provePending" | "bind"> {
	const pendingOf = (subject: string, pending: string) => {
		const value = JSON.parse(opened(pending, sealContext(subject, "pending"))) as Pending;
		const kind = p.kinds.get(value.kind);
		const fences = typeof value.fences === "number" ? value.fences : 0;
		return kind ? { kind, secret: value.secret, first: value.first === true, fences } : undefined;
	};
	return {
		begin: async (subject, name, passed, transaction, from) => {
			const kind = p.kinds.get(name);
			// A way back mfa issues itself is reissued, never begun; any other kind a subject binds.
			if (!kind || issuedWayBack(kind)) return { kind: "unknown-kind" };
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
				...(first ? { first } : {}),
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
			// A mark beside nothing counting is a store that lost its factors: no first binding refills it.
			if (asFirst && p.witnessing) {
				const counts = counting(await records.list(subject), p.kinds).length > 0;
				await standing(subject, counts, "binding");
			}
			const unique = found.kind.uniqueSecret?.({ secret: found.secret, state });
			const fid = id();
			const factor: Factor = {
				id: fid,
				kind: found.kind.kind,
				...(label ? { label } : {}),
				secret: p.seal.seal(found.secret, sealContext(subject, fid)),
				state,
				boundAt: p.now(),
				...(unique !== undefined ? { claims: true as const } : {}),
			};
			const backed = [...p.kinds.values()].some(issuedWayBack);
			// Decided on the factors as written: of two first bindings at once, one binds.
			const judge = (
				all: readonly Factor[],
				fences: number,
			): Decision<"full" | "closed" | "fenced" | { due: boolean }> => {
				if (fences !== found.fences) return { verdict: "fenced" };
				// A first binding another counting factor beat to the subject binds nothing: it was let begin as the first.
				if (asFirst && counting(all, p.kinds).length > 0) return { verdict: "closed" };
				// A subject holding no codes keeps them a place, for the reissue to write them in: only where
				// a factor that counts stands once this one is written, as the reissue asks one.
				const due = backed && !all.some(wayBack) && counting([...all, factor], p.kinds).length > 0;
				if (all.length + 1 + (due ? 1 : 0) > p.maxFactors) return { verdict: "full" };
				return { next: [...all, factor], verdict: { due } };
			};
			// A factor with a unique value is written with its claim on it, at once.
			const written =
				unique === undefined
					? await records.decide(subject, judge)
					: await records.decideClaiming(
							subject,
							{ kind: factor.kind, value: unique, factor: fid },
							judge,
						);
			if (written === "duplicate") return { kind: "duplicate" };
			if (written === "fenced") return { kind: "fenced" };
			if (written === "full") return { kind: "full" };
			if (written === "closed") return closed(subject, factor.kind, "competing");
			const { due } = written;
			// A reset since the write took what was written: nothing stands for this binding.
			if (!(await records.list(subject)).some((f) => f.id === fid)) {
				return closed(subject, factor.kind, "reset-cleared");
			}
			recorded("factor.enrolled", subject, { kind: factor.kind, factor: fid });
			// The mark follows the factor: a write that fails leaves none, and a missing one is filled here.
			await settle(subject);
			return { kind: "bound", factor: shown(factor), fence: found.fences as Fence, codesDue: due };
		},
	};
}
