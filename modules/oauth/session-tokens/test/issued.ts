import { defineModule } from "@mod/kernel";
import { unavailableSwitch } from "@mod/kernel/testing";
import { memoryRecords } from "@mod/records/testing";
import {
	type IssuedTokens,
	issuedTokens,
	pendingSessions,
	type TokenIndex,
	tokenIndex,
} from "../src/store.ts";

/**
 * session-tokens' store interfaces on the records stand-in, at most `size` references to a
 * session, on the composition's clock. `crowd` adds to the same sets past that size.
 */
export function issuedInMemory(size = 1000) {
	let clock = () => 0;
	const memory = memoryRecords<never>(() => clock(), { shards: 1, perShard: 1 });
	const sets = memory.keyedSets(size);
	const crowd = memory.keyedSets(Number.MAX_SAFE_INTEGER);
	// Runs once before the next add, as records made at the same time would.
	let race: (() => Promise<void>) | undefined;
	// Whether the host stops right after the next add's write, before anything after it runs.
	let stopping = false;
	// Runs once before the next settle, as another request's add at that moment would.
	let beforeSettle: (() => Promise<void>) | undefined;
	const place = {
		...sets,
		size,
		add: async (session: string, reference: string, lifetimeMs: number) => {
			const racing = race;
			race = undefined;
			await racing?.();
			const added = await sets.add(session, reference, lifetimeMs);
			if (stopping) {
				stopping = false;
				throw new Error("the host stopped");
			}
			return added;
		},
		settled: async (session: string, reference: string) => {
			const running = beforeSettle;
			beforeSettle = undefined;
			await running?.();
			return sets.settled(session, reference);
		},
	};
	const { records } = memoryRecords<string>(() => clock(), { shards: 1, perShard: 1 });
	const deferred = memoryRecords<never>(() => clock(), { shards: 1, perShard: 100 }).deferred;
	// Runs once before the next session is taken off the list, as another request at that moment would.
	let beforeDone: (() => Promise<void>) | undefined;
	const pending = {
		...deferred,
		done: async (session: string) => {
			const running = beforeDone;
			beforeDone = undefined;
			await running?.();
			return deferred.done(session);
		},
	};
	const down = unavailableSwitch<TokenIndex>("token-index");
	const index = down.wrap({ save: records.create, read: records.read });
	const module = defineModule({ name: "issued-tokens" }, (m) => [
		m.provide(issuedTokens).by((c) => {
			clock = c.clock.now;
			return place satisfies IssuedTokens;
		}),
		m.provide(tokenIndex).by(() => index),
		m.provide(pendingSessions).by(() => pending),
	]);
	const beforeNextAdd = (racing: () => Promise<void>) => {
		race = racing;
	};
	const pendingListed = async () => {
		const found: string[] = [];
		await pending.each(async (session) => {
			found.push(session);
		});
		return found.sort();
	};
	/** Takes the session off the list, as a sweep that found nothing awaiting does. */
	const sweptDone = (session: string) => pending.done(session);
	const beforeNextDone = (running: () => Promise<void>) => {
		beforeDone = running;
	};
	const stopAfterNextAdd = () => {
		stopping = true;
	};
	const beforeNextSettle = (running: () => Promise<void>) => {
		beforeSettle = running;
	};
	return {
		module,
		sets,
		crowd,
		beforeNextAdd,
		records,
		down,
		pendingListed,
		sweptDone,
		beforeNextDone,
		stopAfterNextAdd,
		beforeNextSettle,
	};
}
