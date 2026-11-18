/** What every part of the store contract test shares: the spaces it declares, the harness an implementation gives, and the helpers each part uses. */
import { expect } from "vitest";
import type { Json, Key, Space, Store, Version, WriteOptions } from "../contract.ts";

export const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/** For tests' set-up: writes a key whatever it holds, on the version read or if absent, again on a lost race. */
export async function overwrite(s: Store, key: Key, value: Json, options: WriteOptions) {
	for (let attempt = 0; attempt < 8; attempt++) {
		const { entry } = await s.get(key);
		const answer = entry
			? await s.replaceIf(key, entry.version, value, options)
			: await s.putIfAbsent(key, value, options);
		if (answer.kind === "written" || answer.kind === "late" || answer.kind === "reused") {
			return answer;
		}
	}
	throw new Error("overwrite: the key kept moving");
}

/** The spaces the contract tests use; a harness declares them when it opens a store. */
export const contractSpaces: readonly Space[] = Object.freeze([
	{ name: "contract", guarantees: [] },
	{ name: "contract-replicated", guarantees: ["replicated"] },
	{ name: "contract-confirmed", guarantees: ["replicated", "confirmed-reads"] },
	// The guarantees of the first, so a batch across spaces can join the two.
	{ name: "contract-twin", guarantees: [] },
	// Of subjects' data, the guarantees of the first: a change to it carries the subject writer.
	{ name: "contract-subjects", guarantees: [], subjectData: "online-indexed" },
]);

export interface StoreHarness {
	/** A store over a fresh, empty namespace. */
	open(): Promise<Store>;
	/** Another connection to the same data as `store`. */
	peer(store: Store): Promise<Store>;
	/** For implementations that replicate: stop replicas from acknowledging until the returned undo runs. */
	stopReplicas?(): Promise<() => Promise<void>>;
	/** For implementations over a network: drop the reply to the next command sent through `store`. */
	loseNextReply?(store: Store): Promise<void>;
	/** For implementations with a server: restart it, keeping what it persisted. */
	restart?(): Promise<void>;
	/**
	 * For implementations that replicate: promote a replica in place of the primary while the
	 * replica lacks the latest writes (it may be stopped beforehand); the returned undo restores
	 * the old roles with replicas running.
	 */
	failover?(): Promise<() => Promise<void>>;
}

/** The first answer `attempt` gives without rejecting, trying `tries` times 100 ms apart. */
export async function eventually<T>(
	attempt: () => Promise<T>,
	tries: number,
): Promise<T | undefined> {
	for (let i = 0; i < tries; i++) {
		const answer = await attempt().catch(async () => {
			await sleep(100);
			return undefined;
		});
		if (answer !== undefined) return answer;
	}
	return undefined;
}

/** Reads until the store clock passes `at`, and checks that presence ends exactly at `at`. */
export async function expectPresentUntil(
	at: number,
	read: () => Promise<{ now: number; present: boolean }>,
): Promise<void> {
	const seen: [number, boolean][] = [];
	for (let i = 0; i < 400; i++) {
		const { now, present } = await read();
		seen.push([now, present]);
		if (now > at) break;
		await sleep(1);
	}
	for (const [time, present] of seen) expect([time, present]).toEqual([time, time < at]);
	expect(seen.some(([time]) => time >= at)).toBe(true);
}

/** `count` calls started together, alternating between two connections to the same data. */
export const race = <T>(
	count: number,
	[s, t]: readonly [Store, Store],
	run: (store: Store, i: number) => Promise<T>,
) => Promise.all(Array.from({ length: count }, (_, i) => run(i % 2 ? s : t, i)));

export const versionOf = (answer: { kind: string; version?: Version }): Version => {
	if (answer.kind !== "written" || answer.version === undefined)
		throw new Error(`not written: ${answer.kind}`);
	return answer.version;
};

/** What one run of the contract shares across its parts: the spaces, fresh keys, and two connections. */
export function contractKit(harness: StoreHarness) {
	const [space, replicated, confirmed, twin, subjects] = contractSpaces as [
		Space,
		Space,
		Space,
		Space,
		Space,
	];
	let n = 0;
	/** A partition no other test uses. */
	const partition = () => `p${++n}`;
	/** Keys of `target` in a partition no other test uses. */
	const fresh =
		(target: Space = space, at = partition()) =>
		(name: string): Key => ({ space: target, partition: at, name });
	const never = { expiry: { kind: "never" } } as const;
	const both = async () => {
		const s = await harness.open();
		return [s, await harness.peer(s)] as const;
	};
	return { space, replicated, confirmed, twin, subjects, partition, fresh, never, both };
}

export type ContractKit = ReturnType<typeof contractKit>;
