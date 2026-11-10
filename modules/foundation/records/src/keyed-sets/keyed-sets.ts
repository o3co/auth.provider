import type { Clock } from "@mod/kernel";
import { codePointOrder, type Json } from "@mod/store";
import { expiryOf, type Place, plainDoor, rewrite } from "../writing/writing.ts";

export interface Member {
	readonly member: string;
	readonly remainingMs: number;
}

const clearingMs = 10 * 60_000;

export function overCap<T extends readonly [string, number]>(
	byEnd: readonly T[],
	added: string,
	cap: number,
) {
	const over = Math.max(0, byEnd.length - cap);
	const out = new Set(
		byEnd
			.filter(([name]) => name !== added)
			.slice(0, over)
			.map(([name]) => name),
	);
	return { held: byEnd.filter(([name]) => !out.has(name)), out: [...out] };
}

export function checkedCap(cap: number): number {
	if (!Number.isInteger(cap) || cap < 1)
		throw new TypeError("records: a set's cap is a whole number from 1");
	return cap;
}

/** Sets of members by key, at most `cap` to a key, ending on the kernel's clock; what an add pushes out awaits in the same write. */
export function keyedSetsIn(place: Place & { readonly cap: number; readonly clock: Clock }) {
	plainDoor(place);
	const codec = keyedSetsIn.codec(place);
	const keyOf = (key: string) => ({ space: place.space, partition: key, name: "set" });
	/** Rewrites a set as the codec decides on what it holds. */
	const rewritten = (
		key: string,
		decide: (current: Json | undefined) => KeyedSetWrite | undefined,
	) =>
		rewrite(place, keyOf(key), (current) => {
			const next = decide(current);
			return next && { value: next.value, expiry: expiryOf(next.lifetimeMs) };
		});
	return {
		add: async (
			key: string,
			member: string,
			lifetimeMs: number,
		): Promise<{ readonly pushedOut: readonly string[] }> => {
			// The end is fixed at the add, so a write that lands late never shortens it.
			const ends = place.clock.now() + lifetimeMs;
			let pushedOut: readonly string[] = [];
			await rewritten(key, (current) => {
				const added = codec.add(current, member, ends);
				pushedOut = added.pushedOut;
				return added.next;
			});
			if (pushedOut.length > 0) {
				place.log?.warn("records.pushed_out", { space: place.space.name, count: pushedOut.length });
			}
			return { pushedOut };
		},
		members: async (key: string): Promise<readonly Member[]> => {
			const { entry } = await place.store.get(keyOf(key));
			return codec.members(entry?.value);
		},
		remove: async (key: string, member: string): Promise<void> => {
			await rewritten(key, (current) => codec.remove(current, member));
		},
		awaiting: async (key: string): Promise<readonly string[]> => {
			const { entry } = await place.store.get(keyOf(key));
			return codec.awaiting(entry?.value);
		},
		settled: async (key: string, member: string): Promise<void> => {
			await rewritten(key, (current) => codec.settled(current, member));
		},
	};
}

/** A set to write: its value, and its lifetime from the write. */
export interface KeyedSetWrite {
	readonly value: Json;
	readonly lifetimeMs: number;
}

/**
 * The keyed set's format at rest, its only definition: what a set holds (members with their ends,
 * and those pushed out awaiting), each change made from what it holds, on `clock`, and the
 * lifetime it is kept for. Pure: `keyedSetsIn` writes with it, and subject-records composes it
 * inside `changeRecords`.
 */
keyedSetsIn.codec = (p: { readonly cap: number; readonly clock: Clock }) => {
	const cap = checkedCap(p.cap);
	type Pair = readonly [string, number];
	const isPair = (item: Json): item is Pair =>
		Array.isArray(item) && typeof item[0] === "string" && typeof item[1] === "number";
	const pairsIn = (value: Json | undefined) => (Array.isArray(value) ? value : []).filter(isPair);
	const contentOf = (value: Json | undefined) => {
		if (Array.isArray(value) || typeof value !== "object" || value === null) {
			return { held: pairsIn(value), awaiting: [] as Pair[] };
		}
		const kept = value as { readonly held?: Json; readonly awaiting?: Json };
		return { held: pairsIn(kept.held), awaiting: pairsIn(kept.awaiting) };
	};
	const live = (pairs: readonly Pair[], now: number) => pairs.filter(([, ends]) => ends > now);
	const written = (
		held: readonly Pair[],
		awaiting: readonly Pair[],
		now: number,
	): KeyedSetWrite => {
		const last = Math.max(...held.map(([, end]) => end), ...awaiting.map(([, end]) => end), now);
		return {
			value: { held: [...held], awaiting: [...awaiting] } as Json,
			lifetimeMs: Math.max(1, last - now) + clearingMs,
		};
	};
	const byMember = (pairs: readonly Pair[]) => pairs.map(([member]) => member).sort(codePointOrder);
	return {
		/** Adds `member` until `ends` (a time on `clock`), answering those pushed out over the cap. */
		add: (
			current: Json | undefined,
			member: string,
			ends: number,
		): { readonly next: KeyedSetWrite; readonly pushedOut: readonly string[] } => {
			const now = p.clock.now();
			const content = contentOf(current);
			const kept = new Map(live(content.held, now));
			kept.set(member, Math.max(kept.get(member) ?? 0, ends));
			const byEnd = [...kept].sort((a, b) => a[1] - b[1] || codePointOrder(a[0], b[0]));
			const { held, out } = overCap(byEnd, member, cap);
			const awaiting = new Map(live(content.awaiting, now));
			for (const name of out) awaiting.set(name, kept.get(name) ?? now);
			return { next: written(held, [...awaiting], now), pushedOut: out };
		},
		/** The set without `member`; none where there is no set. */
		remove: (current: Json | undefined, member: string): KeyedSetWrite | undefined => {
			if (current === undefined) return undefined;
			const { held, awaiting } = contentOf(current);
			const now = p.clock.now();
			return written(
				held.filter(([name]) => name !== member),
				live(awaiting, now),
				now,
			);
		},
		/** The set with `member` no longer awaiting; none where there is no set. */
		settled: (current: Json | undefined, member: string): KeyedSetWrite | undefined => {
			if (current === undefined) return undefined;
			const { held, awaiting } = contentOf(current);
			const now = p.clock.now();
			return written(
				held,
				live(awaiting, now).filter(([name]) => name !== member),
				now,
			);
		},
		members: (current: Json | undefined): readonly Member[] => {
			const now = p.clock.now();
			return live(contentOf(current).held, now)
				.map(([member, ends]) => ({ member, remainingMs: ends - now }))
				.sort((a, b) => codePointOrder(a.member, b.member));
		},
		awaiting: (current: Json | undefined): readonly string[] =>
			byMember(live(contentOf(current).awaiting, p.clock.now())),
	};
};

export type KeyedSets = ReturnType<typeof keyedSetsIn>;
