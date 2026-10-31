import { Unavailable } from "@mod/kernel";
import { isLabel } from "@mod/labels";
import type { FactorBinding } from "@mod/mfa-binding";
import { issuedWayBack, type Opened } from "@mod/mfa-extensions";
import type { FactorManaging } from "@mod/mfa-managing";
import type { FactorReading, Fence } from "@mod/mfa-reading";
import { bindingWith } from "./binding/binding.ts";
import { clearingWith } from "./clearing/clearing.ts";
import { type Factor, sealContext } from "./records/records.ts";
import {
	amrOf,
	counting,
	type FactorParts,
	guessing,
	sameState,
	sharedOf,
	shown,
	usable,
} from "./shared.ts";
import { standingWith } from "./standing/standing.ts";

export { addsMfa, byKind, counting, type FactorParts, guessing } from "./shared.ts";

/** mfa's decisions: the members of the three contracts it provides, one implementation in each app. */
export type Decisions = FactorReading & FactorBinding & FactorManaging;

export function factorDecisions(p: FactorParts): Decisions {
	const shared = sharedOf(p);
	const { records, recorded, id, opened, secretOf, resealedSecret, heldOf, wayBack } = shared;
	const standings = standingWith(shared);
	const { standing, standingIds, countsNow, writtenStanding, unclaimedWritten } = standings;
	const clearing = clearingWith(shared, standings);
	const { clear } = clearing;
	const binding = bindingWith(shared, standings, clearing);
	const challengeContext = (subject: string, factor: string) =>
		sealContext(subject, `challenge ${factor}`);
	const recovery = async (subject: string) => {
		const kind = [...p.kinds.values()].find(issuedWayBack);
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
	return {
		held: async (subject) => usable(await records.list(subject), p.kinds).map(shown),
		countingHeld: async (subject, at) => {
			const counts = counting(await records.list(subject), p.kinds).length > 0;
			return (await standing(subject, counts, at)) === "held";
		},
		countingWritten: (subject) => countsNow(subject),
		writtenStanding,
		unclaimedWritten,
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
			if (issuedWayBack(kind)) {
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
		...binding,
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
			// Read before the write: a factor written since, not read here, does not stand for the subject.
			const stood = p.required || p.witnessing ? await standingIds(subject) : new Set<string>();
			const removed = await records.decide<"unknown" | "last" | "fenced" | { kind: string }>(
				subject,
				(all, fences) => {
					if (fences !== fence) return { verdict: "fenced" };
					const kind = all.find((f) => f.id === target)?.kind;
					if (kind === undefined) return { verdict: "unknown" };
					const rest = all.filter((f) => f.id !== target);
					const counted = counting(rest, p.kinds).length > 0;
					// Under a witness only a reset ends an enrollment: its mark stays, so no factor would stand for it.
					// One whose claim is missing may yet be another's, so it does not stand for the subject.
					const stays = rest.some((f) => stood.has(f.id));
					if ((p.required || p.witnessing) && !stays) return { verdict: "last" };
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
