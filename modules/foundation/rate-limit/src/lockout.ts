import { Unavailable } from "@mod/kernel";
import { type Decision, type Json, mutate, type Space, type Store } from "@mod/store";
import type {
	Lockout,
	LockoutPolicy,
	Lockouts,
	Released,
	ReleaseTerms,
	Reserved,
	Standing,
} from "./contract.ts";
import { partitionOf } from "./partition.ts";

/** A release is written by one request and read by another to allow attempts again. */
export const lockoutSpace: Space = {
	name: "rate-limit.lockouts",
	guarantees: ["no-eviction", "durable", "replicated", "confirmed-reads"],
};

type State = {
	/** Failures in the current run, and when the last one was. */
	readonly run: number;
	readonly lastAt: number;
	/** Failure times within the budget window, oldest first. */
	readonly spent: readonly number[];
	readonly holdUntil: number;
	readonly fixed: boolean;
	/** The attempt that fixed the hold; while reserved, its success may still hand it back. */
	readonly fixedAt?: number;
	/** The last attempt time handed out; it never goes back, whatever is handed back or ages out. */
	readonly named?: number;
	/** Releases applied to the key; a state holding one is kept with no expiry, so the count never goes back. */
	readonly generation?: number;
	/** Release ids applied, each until it may be applied again. */
	readonly used?: readonly { readonly id: string; readonly until: number }[];
};

type Hold = Extract<Lockout, { kind: "held" }>["hold"];

const empty: State = { run: 0, lastAt: 0, spent: [], holdUntil: 0, fixed: false };
const stateOf = (value: Json | null | undefined): State =>
	value && typeof value === "object" && !Array.isArray(value) ? (value as State) : empty;

/** The state as of `now`: a quiet run is forgotten; failures older than the budget window and ids past keeping drop out. */
function aged(state: State, policy: LockoutPolicy, now: number): State {
	const spent = state.spent.filter((at) => at > now - policy.budgetWindowMs);
	const quiet = !state.fixed && state.lastAt > 0 && now - state.lastAt > policy.memoryMs;
	const used = state.used ? { used: state.used.filter((u) => u.until > now) } : {};
	return quiet ? { ...state, run: 0, spent, ...used } : { ...state, spent, ...used };
}

/** What every rewrite carries over: the attempt times handed out, and the releases. */
const kept = (state: State): Partial<State> => ({
	...(state.named === undefined ? {} : { named: state.named }),
	...(state.generation === undefined ? {} : { generation: state.generation }),
	...(state.used?.length ? { used: state.used } : {}),
});

const fixedOf = (state: State) =>
	state.fixed && state.fixedAt !== undefined ? { fixedAt: state.fixedAt } : {};

function standingOf(state: State): Standing {
	const first = state.spent[0];
	return { ...(first === undefined ? {} : { firstFailureAt: first }), ...fixedOf(state) };
}

/** Judges a release on the state as of the write; no `next` when nothing is written. */
function released(
	was: State,
	terms: ReleaseTerms,
	now: number,
): { readonly next: State; readonly answer: Released } | { readonly answer: Released } {
	const nextGeneration = (was.generation ?? 0) + 1;
	if (terms.kind === "whole") {
		const next: State = { ...empty, ...kept(was), generation: nextGeneration };
		const cleared = { budget: true, run: true, hard: true };
		return { next, answer: { kind: "released", generation: nextGeneration, cleared } };
	}
	if (was.used?.some((u) => u.id === terms.once.id)) {
		return { answer: { kind: "already", generation: was.generation ?? 0, ...fixedOf(was) } };
	}
	const stands = standingOf(was);
	const forgiven =
		terms.forgive !== undefined && terms.forgive.firstFailureAt === stands.firstFailureAt;
	const lifted = terms.lift !== undefined && terms.lift.fixedAt === stands.fixedAt;
	if (!forgiven && !lifted) return { answer: { kind: "unchanged", ...fixedOf(was) } };
	const staysFixed = was.fixed && !lifted;
	const endsRun = lifted || (forgiven && !staysFixed);
	const next: State = {
		...kept(was),
		run: endsRun ? 0 : was.run,
		lastAt: was.lastAt,
		spent: forgiven ? [] : was.spent,
		holdUntil: endsRun ? 0 : was.holdUntil,
		fixed: staysFixed,
		...(staysFixed ? fixedOf(was) : {}),
		generation: nextGeneration,
		used: [...(was.used ?? []), { id: terms.once.id, until: now + terms.once.keepMs }],
	};
	const cleared = { budget: forgiven, run: endsRun, hard: lifted };
	const answer: Released = {
		kind: "released",
		generation: nextGeneration,
		cleared,
		...fixedOf(next),
	};
	return { next, answer };
}

function judge(state: State, policy: LockoutPolicy, now: number): Lockout {
	if (state.fixed) return { kind: "held", hold: "hard" };
	if (state.holdUntil > now)
		return { kind: "held", hold: "backoff", retryAfterMs: state.holdUntil - now };
	if (state.spent.length >= policy.budget) {
		const oldest = state.spent[0] ?? now;
		return { kind: "held", hold: "budget", retryAfterMs: oldest + policy.budgetWindowMs - now };
	}
	return { kind: "open" };
}

export interface LockoutStates {
	read(name: string, key: string): Promise<{ readonly value?: Json; readonly now: number }>;
	change(
		name: string,
		key: string,
		decide: (value: Json | undefined, now: number) => Decision,
	): Promise<void>;
}

export function storedStates(saved: Store): LockoutStates {
	const keyOf = (name: string, key: string) => ({
		space: lockoutSpace,
		partition: partitionOf(name, key),
		name: "lockout",
	});
	return {
		read: async (name, key) => {
			const { entry, now } = await saved.get(keyOf(name, key));
			return entry ? { value: entry.value, now } : { now };
		},
		change: async (name, key, decide) => {
			const done = await mutate(saved, keyOf(name, key), (current, now) =>
				decide(current?.value, now),
			);
			if (done.kind !== "done") throw new Unavailable("rate-limit");
		},
	};
}

export function lockoutCounter(states: LockoutStates): Lockouts {
	const keptMs = (policy: LockoutPolicy) => Math.max(policy.budgetWindowMs, policy.memoryMs);
	const expiryOf = (next: State, policy: LockoutPolicy) =>
		next.fixed || next.generation !== undefined
			? { kind: "never" as const }
			: { kind: "after" as const, ms: keptMs(policy) };
	/** Changes the key, answering what the last run of `decide` (the one written) decided; mutate runs it again on a lost race. */
	const changing = async <T>(
		name: string,
		key: string,
		decide: (
			current: Json | undefined,
			now: number,
		) => { readonly decision: Decision; readonly answer: T },
	): Promise<T> => {
		let last: { readonly answer: T } | undefined;
		await states.change(name, key, (current, now) => {
			const run = decide(current, now);
			last = run;
			return run.decision;
		});
		return (last as { readonly answer: T }).answer;
	};
	/** Counts one failure; a reservation leaves a key already held as it is. */
	const record = (
		name: string,
		key: string,
		policy: LockoutPolicy,
		as: "failure" | "reservation",
	) =>
		changing<{ readonly lockout: Lockout; readonly at: number; readonly holds?: Hold }>(
			name,
			key,
			(current, now) => {
				const was = aged(stateOf(current), policy, now);
				// Each attempt's time is unique within the key, so a reservation names one attempt.
				const at = Math.max(now, (was.named ?? 0) + 1);
				const before = judge(was, policy, now);
				if (as === "reservation" && before.kind === "held") {
					return { decision: { kind: "keep" }, answer: { lockout: before, at } };
				}
				const run = was.run + 1;
				const over = run - policy.threshold;
				const holdMs = over < 0 ? 0 : Math.min(policy.backoffMs * 2 ** over, policy.maxBackoffMs);
				const fixed = was.fixed || run >= policy.hardLimit;
				// The attempt that fixes the hold names it; one already fixed keeps its own.
				const fixedAt = was.fixed ? was.fixedAt : fixed ? at : undefined;
				const next: State = {
					...kept(was),
					run,
					lastAt: now,
					spent: [...was.spent, at].slice(-policy.budget),
					holdUntil: holdMs > 0 ? now + holdMs : was.holdUntil,
					fixed,
					named: at,
					...(fixedAt === undefined ? {} : { fixedAt }),
				};
				const left = judge(next, policy, now);
				const decision: Decision = { kind: "write", value: next, expiry: expiryOf(next, policy) };
				if (as === "failure") return { decision, answer: { lockout: left, at } };
				const holds = left.kind === "held" ? { holds: left.hold } : {};
				return { decision, answer: { lockout: { kind: "open" }, at, ...holds } };
			},
		);
	/** Hands back a reserved attempt: a success ends the run; an abandoned one leaves it one shorter. */
	const handBack = async (
		name: string,
		key: string,
		policy: LockoutPolicy,
		reservation: number | undefined,
		how: "success" | "abandoned",
	) => {
		await states.change(name, key, (current, now) => {
			if (current === undefined) return { kind: "keep" };
			const was = aged(stateOf(current), policy, now);
			const index = reservation === undefined ? -1 : was.spent.lastIndexOf(reservation);
			if (how === "abandoned" && index < 0) return { kind: "keep" };
			// A fixed hold stays, unless the attempt handed back is the very one that fixed it.
			if (was.fixed && (index < 0 || was.fixedAt !== reservation)) return { kind: "keep" };
			const spent = index < 0 ? was.spent : was.spent.toSpliced(index, 1);
			const run = how === "success" ? 0 : Math.max(0, was.run - 1);
			// A reservation is made only while open, so a hold left by the last attempt is its own.
			const own = index >= 0 && index === was.spent.length - 1;
			const holdUntil = run < policy.threshold || own ? 0 : was.holdUntil;
			const next: State = { ...kept(was), run, lastAt: was.lastAt, holdUntil, spent, fixed: false };
			const expiry = was.fixed ? expiryOf(next, policy) : { kind: "keep" as const };
			return { kind: "write", value: next, expiry };
		});
	};
	return {
		check: async (name, key, policy) => {
			const { value, now } = await states.read(name, key);
			return judge(aged(stateOf(value), policy, now), policy, now);
		},
		failed: async (name, key, policy) => (await record(name, key, policy, "failure")).lockout,
		reserve: async (name, key, policy): Promise<Reserved> => {
			const { lockout, at, holds } = await record(name, key, policy, "reservation");
			if (lockout.kind === "held") return lockout;
			return { kind: "open", reservation: at, ...(holds ? { holds } : {}) };
		},
		succeeded: async (name, key, policy, reservation) => {
			await handBack(name, key, policy, reservation, "success");
		},
		abandoned: async (name, key, policy, reservation) => {
			await handBack(name, key, policy, reservation, "abandoned");
		},
		standing: async (name, key, policy) => {
			const { value, now } = await states.read(name, key);
			return standingOf(aged(stateOf(value), policy, now));
		},
		releaseUnder: (name, key, policy, terms) =>
			changing(name, key, (current, now) => {
				const done = released(aged(stateOf(current), policy, now), terms, now);
				const decision: Decision =
					"next" in done
						? { kind: "write", value: done.next, expiry: expiryOf(done.next, policy) }
						: { kind: "keep" };
				return { decision, answer: done.answer };
			}),
	};
}
