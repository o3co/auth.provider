import { defineModule, type Module, Unavailable } from "@mod/kernel";
import {
	checkedStore,
	type Guarantee,
	type Key,
	type Space,
	type Store,
	spaces,
	store,
} from "./contract.ts";
import { memoryStore } from "./memory.ts";

const writes = new Set<string>([
	"putIfAbsent",
	"replaceIf",
	"removeIf",
	"take",
	"batch",
	"batchAcross",
	"count",
]);
const pause = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
const writtenKinds = new Set(["written", "removed", "taken", "committed", "counted"]);

/** A store with a primary and a replica, for testing what users of the store do under faults. */
export interface SimulatedStore {
	/** Provides the store, over the spaces declared in the composition. */
	readonly module: Module;
	/** The next write is applied on the primary, but answered as unavailable and not confirmed. */
	loseNextReply(): void;
	/** While on, writes are unavailable and not applied; reads still answer. */
	failWrites(on: boolean): void;
	/** The next call of this operation is unavailable and not applied; other calls answer as before. */
	failNext(operation: keyof Store): void;
	/** Runs `run` just before the next call of this operation on this space, as another client would. */
	beforeNext(operation: keyof Store, space: string, run: () => Promise<void>): void;
	/**
	 * Runs `run` once the next write of this operation on this space has applied on the primary and
	 * before it is confirmed, as another client would; a write a failover loses meanwhile is unavailable.
	 */
	beforeConfirm(operation: keyof Store, space: string, run: () => Promise<void>): void;
	/** While on, every operation is unavailable. */
	unreachable(on: boolean): void;
	/** The replica takes over; what was not confirmed is lost. A write is confirmed by the answer to
	 * itself or to a later write in a replicated space, never by a write in a space without one. */
	failover(): Promise<void>;
	/** The store restarts: spaces that are not durable lose everything, on the primary and the replica. */
	restart(): Promise<void>;
	/** Memory runs short: spaces not kept from eviction lose everything, on the primary and the replica. */
	pressMemory(): Promise<void>;
	/** Moves the store clock away from the composition's clock. */
	shiftClock(ms: number): void;
	/**
	 * While on, replicas take nothing: writes in replicated spaces apply on the primary and wait a
	 * while for their confirmation, answering others meanwhile, then fail; confirmed reads fail;
	 * other spaces answer as before.
	 */
	stallReplicas(on: boolean): void;
	/** Whether any write it ever took, kept now or lost, carried `text` in a key or a value. */
	holds(text: string): boolean;
}

function spaceOf(name: string, args: readonly unknown[]): Space | undefined {
	switch (name) {
		// A batch across joins spaces of one guarantee only, so its first key's space stands for all.
		case "batch":
		case "batchAcross": {
			const [conditions, written] = args as [readonly { key: Key }[], readonly { key: Key }[]];
			return (conditions[0] ?? written[0])?.key.space;
		}
		default:
			return (args[0] as Key | undefined)?.space;
	}
}

/** A write as the primary took it: replayed on its own time, naming the versions it named then. */
interface Logged {
	readonly name: string;
	readonly args: readonly unknown[];
	readonly at: number;
	readonly versions: readonly string[];
}

/** A simulated replicated store; versions come from one count, so a failover never repeats one. */
export function simulatedStore(): SimulatedStore {
	let shift = 0;
	let loseNext = false;
	let writesFail = false;
	let down = false;
	let stalled = false;
	const failing = new Set<keyof Store>();
	type Hook = { operation: keyof Store; space: string; run: () => Promise<void> };
	const before: Hook[] = [];
	const confirming: Hook[] = [];
	const runHook = async (hooks: Hook[], name: string, space: Space | undefined) => {
		const at = hooks.findIndex((h) => h.operation === name && h.space === space?.name);
		if (at >= 0) await hooks.splice(at, 1)[0]?.run();
	};
	const state: {
		primary?: Store;
		replica?: Store;
		open?: () => Store;
		pending: Logged[];
		confirmed: Logged[];
	} = { pending: [], confirmed: [] };
	let storeNow = () => 0;
	let lastVersion = 0;
	const everWritten: string[] = [];
	let minted: string[] = [];
	/** A write's decision time and versions, the same on the primary and in its replay. */
	let applying: { at: number; versions: string[] } | undefined;
	const clock = { now: () => applying?.at ?? storeNow() };
	const nextVersion = () => {
		const replayed = applying?.versions.shift();
		if (replayed !== undefined) return replayed;
		const version = String(++lastVersion);
		minted.push(version);
		return version;
	};
	let queue: Promise<unknown> = Promise.resolve();
	/** Runs one operation at a time, as the store applies them, so no two share a replay or a count. */
	const inTurn = <A>(run: () => Promise<A>): Promise<A> => {
		const turn = queue.then(run);
		// A failed turn rejects its own caller only; the next turn still runs.
		queue = turn.catch(() => {});
		return turn;
	};
	const call = (target: Store, name: string, args: readonly unknown[]) =>
		(target as unknown as Record<string, (...a: unknown[]) => Promise<{ kind?: string }>>)[name]?.(
			...args,
		) as Promise<{ kind?: string }>;
	const replay = async (target: Store, log: readonly Logged[]) => {
		for (const { name, args, at, versions } of log) {
			applying = { at, versions: [...versions] };
			try {
				await call(target, name, args);
			} finally {
				applying = undefined;
			}
		}
	};
	/** Brings the replica up to everything the primary holds. */
	const confirm = async () => {
		await replay(state.replica as Store, state.pending);
		state.confirmed.push(...state.pending);
		state.pending = [];
	};
	/** Rebuilds the primary and the replica from what they held, keeping only spaces that hold to `kept`. */
	const keepOnly = async (kept: Guarantee) => {
		const keeps = ({ name, args }: Logged) =>
			spaceOf(name, args)?.guarantees.includes(kept) ?? false;
		const open = state.open as () => Store;
		state.confirmed = state.confirmed.filter(keeps);
		state.pending = state.pending.filter(keeps);
		state.replica = open();
		await replay(state.replica, state.confirmed);
		state.primary = open();
		await replay(state.primary, [...state.confirmed, ...state.pending]);
	};
	const apply = async (
		name: string,
		args: readonly unknown[],
		space: Space | undefined,
	): Promise<{ answer: unknown; toConfirm: Logged | undefined }> => {
		const primary = state.primary as Store;
		const guarantees: readonly Guarantee[] = space?.guarantees ?? [];
		const confirmsReads = guarantees.includes("confirmed-reads");
		if (!writes.has(name)) {
			if (stalled && confirmsReads) throw new Unavailable("store");
			const read = await call(primary, name, args);
			if (confirmsReads) await confirm();
			return { answer: read, toConfirm: undefined };
		}
		if (writesFail) throw new Unavailable("store");
		const writtenAt = storeNow();
		// nextVersion records here the versions the primary names during this call.
		minted = [];
		applying = { at: writtenAt, versions: [] };
		let answer: { kind?: string };
		try {
			answer = await call(primary, name, args);
		} finally {
			applying = undefined;
		}
		const written = writtenKinds.has(answer?.kind ?? "");
		// A refusing answer is kept too: a resend under its mark must get it again on a replica.
		const logged: Logged = { name, args, at: writtenAt, versions: minted };
		state.pending.push(logged);
		everWritten.push(JSON.stringify(args));
		if (loseNext) {
			loseNext = false;
			throw new Unavailable("store");
		}
		const confirms = written ? guarantees.includes("replicated") : confirmsReads;
		return { answer, toConfirm: confirms ? logged : undefined };
	};
	/** Confirms a write applied before, in a turn of its own; one a failover lost is unavailable. */
	const confirmWrite = async (logged: Logged) => {
		if (stalled) throw new Unavailable("store");
		if (state.pending.includes(logged)) await confirm();
		else if (!state.confirmed.includes(logged)) throw new Unavailable("store");
	};
	/** How long a write waits for stalled replicas before it fails. */
	const holdMs = 100;
	const facade = new Proxy({} as Store, {
		get: (_, name) => {
			if (name === "then") return undefined;
			const operation = String(name);
			return async (...args: unknown[]) => {
				if (down) throw new Unavailable("store");
				if (failing.delete(operation as keyof Store)) throw new Unavailable("store");
				const space = spaceOf(operation, args);
				await runHook(before, operation, space);
				const { answer, toConfirm } = await inTurn(() => apply(operation, args, space));
				if (!toConfirm) return answer;
				await runHook(confirming, operation, space);
				for (let waited = 0; stalled && waited < holdMs; waited += 10) await pause(10);
				await inTurn(() => confirmWrite(toConfirm));
				return answer;
			};
		},
	});
	return {
		module: defineModule({ name: "store", replicaSafe: false, takes: [spaces] }, (m) => [
			m.provide(store).by(async (c) => {
				const declared = await c.collect(spaces);
				storeNow = () => c.clock.now() + shift;
				state.open = () => memoryStore(clock, declared, nextVersion);
				state.primary = state.open();
				state.replica = state.open();
				// Inputs are read once into copies whose keys carry the declared space, for replays too.
				return checkedStore(facade, declared);
			}),
		]),
		loseNextReply: () => {
			loseNext = true;
		},
		failNext: (operation) => {
			failing.add(operation);
		},
		beforeNext: (operation, space, run) => {
			before.push({ operation, space, run });
		},
		beforeConfirm: (operation, space, run) => {
			confirming.push({ operation, space, run });
		},
		failWrites: (on) => {
			writesFail = on;
		},
		unreachable: (on) => {
			down = on;
		},
		failover: () =>
			inTurn(async () => {
				const open = state.open as () => Store;
				state.primary = state.replica as Store;
				state.pending = [];
				state.replica = open();
				await replay(state.replica, state.confirmed);
			}),
		restart: () => inTurn(() => keepOnly("durable")),
		pressMemory: () => inTurn(() => keepOnly("no-eviction")),
		shiftClock: (ms) => {
			shift += ms;
		},
		stallReplicas: (on) => {
			stalled = on;
		},
		// Escapes text as it appears inside a JSON string, since the arguments were kept as JSON.
		holds: (text) => everWritten.some((args) => args.includes(JSON.stringify(text).slice(1, -1))),
	};
}
