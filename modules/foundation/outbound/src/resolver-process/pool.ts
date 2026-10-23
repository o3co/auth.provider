/** A pool of name lookups run in one helper process, which is ended where no one waits on any. */
import { isIP } from "node:net";
import { type HelperProcess, type StartHelper, startHelper } from "./process.ts";

/** Why a lookup gives no addresses: the name's own answer, the helper failing, or the pool stopped. */
export type ResolutionFailure = "not-found" | "too-many" | "fault" | "refusing" | "stopped";

export class ResolutionFailed extends Error {
	readonly reason: ResolutionFailure;
	constructor(reason: ResolutionFailure) {
		super(`the name was not resolved: ${reason}`);
		this.reason = reason;
	}
}

/** One lookup in a pool: its answer, and the interest of those waiting on it. */
export interface Job {
	readonly answer: Promise<readonly string[]>;
	/** One more waits on it; false where it can no longer be waited on (its helper is being ended). */
	want(): boolean;
	/** One fewer waits on it. */
	unwant(): void;
}

export interface ResolverPool {
	/** Starts the helper and waits until it is ready; rejects, starting nothing again, where it is not. */
	start(): Promise<void>;
	/** Ends the helper, whatever it is doing, and waits for it; any number of times. */
	stop(): Promise<void>;
	/** A lookup, where the helper is ready and a place is free; none otherwise. */
	run(name: string, family?: 4): Job | undefined;
}

/** A timer of the pool's own recovery, never keeping the parent alive, as the card says. */
const background = (run: () => void, ms: number) => {
	const timer = setTimeout(run, ms);
	timer.unref();
	return timer;
};

export type Warn = (event: string, fields: Readonly<Record<string, string | number>>) => void;

/** How long a helper may take to be ready, how many addresses an answer may hold, and the windows of restarts. */
export const poolLimits = {
	readyMs: 5_000,
	maxAddresses: 64,
	stuckMs: 30_000,
	windowMs: 60_000,
	faultRestarts: 30,
	abandonRestarts: 60,
	backoffMs: 100,
	maxBackoffMs: 5_000,
};

/** The codes a lookup's error is answered with; any other is a helper's fault. */
const codes = new Set([
	"ENOTFOUND",
	"ENODATA",
	"EAI_AGAIN",
	"EAI_FAIL",
	"EAI_NONAME",
	"EAI_NODATA",
	"EAI_FAMILY",
	"EAI_ADDRFAMILY",
	"EAI_SERVICE",
	"EAI_MEMORY",
	"EAI_SYSTEM",
	"EAI_BADFLAGS",
	"EAI_OVERFLOW",
]);

type Settle = (outcome: { addresses: readonly string[] } | { failure: ResolutionFailure }) => void;

interface Running {
	readonly family?: 4;
	interest: number;
	readonly settle: Settle;
}

type State = "spawning" | "ready" | "isolating" | "stopping" | "dead";
type Reason = "abandoned" | "ipc" | "answer" | "ready-timeout" | "exit" | "spawn-failed";

interface Helper {
	readonly gen: number;
	readonly process: HelperProcess | undefined;
	state: State;
	readonly running: Map<number, Running>;
	reason?: Reason;
	stuck?: NodeJS.Timeout;
	readyTimer?: NodeJS.Timeout;
	readonly exited: Promise<void>;
	markExited: () => void;
}

/**
 * A pool of `size` lookups at once in one helper, named `pool` in what it logs. A helper whose
 * running lookups are all left without anyone waiting is ended and started again; one that fails
 * is ended and started again after a backoff, within the windows of `poolLimits`.
 */
export function resolverPool(options: {
	readonly pool: string;
	readonly size: number;
	readonly warn: Warn;
	/** The kernel's clock, in ms. */
	readonly now: () => number;
	readonly start?: StartHelper;
}): ResolverPool {
	const { pool, size, warn, now } = options;
	const start = options.start ?? startHelper;
	let helper: Helper | undefined;
	let generation = 0;
	let nextId = 0;
	let stopped = false;
	/** Places held: every lookup not yet released, those of a helper being ended among them. */
	let held = 0;
	let backoff = poolLimits.backoffMs;
	let recovering = false;
	let restartTimer: NodeJS.Timeout | undefined;
	let recheckTimer: NodeJS.Timeout | undefined;
	let refusingUntil = 0;
	const faults: number[] = [];
	const abandons: number[] = [];
	let starting: { resolve: () => void; reject: (error: Error) => void } | undefined;
	let firstStart: Promise<void> | undefined;

	const recent = (times: number[]) => {
		const since = now() - poolLimits.windowMs;
		while (times.length > 0 && (times[0] as number) <= since) times.shift();
		return times.length;
	};

	/** Keeps the parent alive while someone waits on the helper's lookups, and lets it go otherwise. */
	const hold = (h: Helper) => {
		// The first start is waited on: the parent is held until it is ready or its end is seen.
		if (starting !== undefined) return h.process?.hold(true);
		if (h.state !== "ready" && h.state !== "spawning") return;
		h.process?.hold([...h.running.values()].some((r) => r.interest > 0));
	};

	const spawn = () => {
		const gen = ++generation;
		let markExited = () => {};
		const exited = new Promise<void>((resolve) => {
			markExited = resolve;
		});
		let child: HelperProcess | undefined;
		try {
			child = start(gen, size);
		} catch {
			child = undefined;
		}
		const h: Helper = {
			gen,
			process: child,
			state: "spawning",
			running: new Map(),
			exited,
			markExited,
		};
		helper = h;
		// Taken before anything else: a process never started reports so later, as an error.
		child?.on("error", () => {
			if (h.process?.pid === undefined) dead(h);
			else isolate(h, "ipc");
		});
		if (child === undefined || child.pid === undefined) {
			// Never started: no process to end, and no exit will come.
			h.reason = "spawn-failed";
			queueMicrotask(() => dead(h));
			return;
		}
		child.on("message", (message) => received(h, message));
		child.on("exit", () => dead(h));
		child.on("disconnect", () => isolate(h, "ipc"));
		h.readyTimer = background(() => isolate(h, "ready-timeout"), poolLimits.readyMs);
		hold(h);
	};

	/** Begins ending a helper: killed once, no more lookups, its places held until it is gone. */
	const isolate = (h: Helper, reason: Reason) => {
		if (h.state === "isolating" || h.state === "stopping" || h.state === "dead") return;
		clearTimeout(h.readyTimer);
		h.state = "isolating";
		h.reason = reason;
		if (reason !== "abandoned") {
			warn("outbound.resolver_fault", { pool, reason });
			for (const running of h.running.values()) running.settle({ failure: "fault" });
		}
		// Let go, but while the first start waits on it: then held until its end is seen.
		h.process?.hold(starting !== undefined);
		h.process?.kill();
		h.stuck = setInterval(() => warn("outbound.resolver_stuck", { pool }), poolLimits.stuckMs);
		h.stuck.unref();
	};

	/** The helper's end, confirmed: the one way its places are given back and a next one decided. */
	const dead = (h: Helper) => {
		if (h.state === "dead") return;
		clearTimeout(h.readyTimer);
		clearInterval(h.stuck);
		// A look again was for this helper's lookups; the next one schedules its own.
		clearTimeout(recheckTimer);
		recheckTimer = undefined;
		h.state = "dead";
		h.markExited();
		if (h.reason === undefined) {
			h.reason = "exit";
			warn("outbound.resolver_fault", { pool, reason: "exit" });
		} else if (h.reason === "spawn-failed") {
			warn("outbound.resolver_fault", { pool, reason: "spawn-failed" });
		}
		for (const running of h.running.values()) running.settle({ failure: "fault" });
		held -= h.running.size;
		h.running.clear();
		if (helper === h) helper = undefined;
		if (starting !== undefined) {
			// The first start's failure is final: nothing is started again.
			const failed = starting;
			starting = undefined;
			stopped = true;
			failed.reject(new Error(`the ${pool} resolver did not start: ${h.reason}`));
			return;
		}
		if (stopped) return;
		if (h.reason === "abandoned") {
			abandons.push(now());
			spawn();
			return;
		}
		faults.push(now());
		recovering = true;
		if (recent(faults) > poolLimits.faultRestarts) {
			refusingUntil = (faults[0] as number) + poolLimits.windowMs;
			warn("outbound.resolver_restarts", { pool, restarts: recent(faults) });
			restartTimer = background(spawn, Math.max(0, refusingUntil - now()));
			return;
		}
		restartTimer = background(spawn, backoff);
		backoff = Math.min(backoff * 2, poolLimits.maxBackoffMs);
	};

	/** Whether every running lookup of the helper is left without anyone waiting; then it is ended, within its window. */
	const abandoned = (h: Helper) => {
		if (h.state !== "ready" || h.running.size === 0) return;
		if ([...h.running.values()].some((r) => r.interest > 0)) return;
		if (recent(abandons) >= poolLimits.abandonRestarts) {
			// Kept for now, its places held; looked at again once the window lets one more go.
			if (recheckTimer === undefined) {
				const at = (abandons[0] as number) + poolLimits.windowMs;
				recheckTimer = background(
					() => {
						recheckTimer = undefined;
						if (helper === h) abandoned(h);
					},
					Math.max(0, at - now()),
				);
			}
			return;
		}
		isolate(h, "abandoned");
	};

	const answerOf = (running: Running, message: Record<string, unknown>) => {
		const { addresses, code } = message;
		if ((addresses === undefined) === (code === undefined)) return undefined;
		if (code !== undefined) {
			return typeof code === "string" && codes.has(code)
				? { failure: "not-found" as const }
				: undefined;
		}
		if (!Array.isArray(addresses) || addresses.length === 0) return undefined;
		const valid = addresses.every(
			(a) => typeof a === "string" && isIP(a) !== 0 && (running.family !== 4 || isIP(a) === 4),
		);
		if (!valid) return undefined;
		return addresses.length > poolLimits.maxAddresses
			? { failure: "too-many" as const }
			: { addresses: addresses as string[] };
	};

	const received = (h: Helper, message: unknown) => {
		if (h.state !== "spawning" && h.state !== "ready") return;
		if (typeof message !== "object" || message === null) return isolate(h, "answer");
		const m = message as Record<string, unknown>;
		if (m.gen !== h.gen) return isolate(h, "answer");
		if (m.ready === true && h.state === "spawning") {
			clearTimeout(h.readyTimer);
			h.state = "ready";
			const started = starting;
			starting = undefined;
			hold(h);
			started?.resolve();
			return;
		}
		const running = typeof m.id === "number" ? h.running.get(m.id) : undefined;
		if (h.state !== "ready" || running === undefined) return isolate(h, "answer");
		const outcome = answerOf(running, m);
		if (outcome === undefined) return isolate(h, "answer");
		h.running.delete(m.id as number);
		held -= 1;
		running.settle(outcome);
		if (recovering) {
			recovering = false;
			backoff = poolLimits.backoffMs;
			warn("outbound.resolver_recovered", { pool });
		}
		hold(h);
		// Those left running may all be left by now: the last one waited on has ended.
		abandoned(h);
	};

	return {
		// One start, shared by every call: a pool never runs two helpers of its own.
		start: () => {
			firstStart ??= new Promise<void>((resolve, reject) => {
				if (stopped) return reject(new Error(`the ${pool} resolver is stopped`));
				starting = { resolve, reject };
				spawn();
			});
			return firstStart;
		},
		stop: async () => {
			stopped = true;
			clearTimeout(restartTimer);
			clearTimeout(recheckTimer);
			if (starting !== undefined) {
				const failed = starting;
				starting = undefined;
				failed.reject(new Error(`the ${pool} resolver is stopped`));
			}
			const h = helper;
			if (h === undefined) return;
			if (h.state !== "dead" && h.state !== "stopping") {
				// Stopping is not undone: nothing taken, nothing waited on, a disconnect or error ignored.
				const killed = h.state === "isolating";
				clearTimeout(h.readyTimer);
				clearInterval(h.stuck);
				h.state = "stopping";
				h.reason ??= "abandoned";
				for (const running of h.running.values()) running.settle({ failure: "stopped" });
				// Held until its end is seen, so the parent waits for it.
				h.process?.hold(true);
				if (!killed) h.process?.kill();
				if (h.process === undefined || h.process.pid === undefined) dead(h);
			}
			await h.exited;
		},
		run: (name, family) => {
			if (stopped) return undefined;
			if (now() < refusingUntil) {
				const refused = Promise.reject(new ResolutionFailed("refusing"));
				// An answer no one waits on is let go unread, as any other.
				refused.catch(() => {});
				return {
					answer: refused,
					want: () => false,
					unwant: () => {},
				};
			}
			const h = helper;
			if (h === undefined || h.state !== "ready" || held >= size) return undefined;
			const id = ++nextId;
			let settle: Settle = () => {};
			const answer = new Promise<readonly string[]>((resolve, reject) => {
				let done = false;
				settle = (outcome) => {
					if (done) return;
					done = true;
					if ("addresses" in outcome) resolve(outcome.addresses);
					else reject(new ResolutionFailed(outcome.failure));
				};
			});
			// An answer no one waits on is let go unread.
			answer.catch(() => {});
			const running: Running = { ...(family ? { family } : {}), interest: 1, settle };
			h.running.set(id, running);
			held += 1;
			h.process?.send({ id, name, ...(family ? { family } : {}) });
			hold(h);
			return {
				answer,
				want: () => {
					if (h.state !== "ready" || !h.running.has(id)) return false;
					running.interest += 1;
					hold(h);
					return true;
				},
				unwant: () => {
					if (running.interest === 0) return;
					running.interest -= 1;
					hold(h);
					abandoned(h);
				},
			};
		},
	};
}
