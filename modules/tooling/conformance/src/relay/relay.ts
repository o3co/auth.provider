import { createConnection, createServer, type Socket } from "node:net";
import { type Command, commandOf, frames, type Reply } from "./resp.ts";

export type { Command, Reply } from "./resp.ts";

/** Which requests a fault is about, and which of their answers show a write that took effect. */
export interface Match {
	readonly request: (command: Command) => boolean;
	readonly succeeded: (reply: Reply) => boolean;
}

export type Role = "operations" | "confirming";

export interface Upstream {
	readonly host: string;
	readonly port: number;
}

/** A request Redis answered, on which connection and when (the relay's monotonic clock, ms). */
export interface Execution {
	readonly connection: number;
	readonly command: Command;
	readonly reply: Reply;
	readonly succeeded: boolean;
	readonly at: number;
}

/** A dropped answer, and the requests behind it on its connection, cut with it. */
export interface Dropped extends Execution {
	readonly collateral: readonly { readonly command: Command; readonly answered: boolean }[];
}

export interface Drop {
	/** The first matched answer that showed a write; rejected where it showed none. */
	readonly first: Promise<Dropped>;
	/** The answers to resends dropped after it, so far. */
	readonly resends: readonly Dropped[];
	end(): void;
}

export interface Held {
	readonly connection: number;
	readonly command: Command;
	/** Sends it and what followed it on its connection; nothing where the connection was cut. */
	release(): void;
}

export interface Connection {
	readonly id: number;
	readonly role: Role | undefined;
	readonly upstream: Upstream;
	readonly open: boolean;
}

export interface RelayOptions {
	readonly upstream: Upstream;
	/** A connection's role, from a request it sends; none leaves it as it was. */
	readonly roleOf?: (command: Command) => Role | undefined;
}

type Direction = "up" | "down";

export const upstreamOf = (url: string): Upstream => {
	const { hostname, port } = new URL(url);
	return { host: hostname, port: Number(port || 6379) };
};

/** A promise whose rejection, left unread, does not end the run. */
function settleable<T>() {
	let resolve!: (value: T) => void;
	let reject!: (error: Error) => void;
	const promise = new Promise<T>((res, rej) => {
		resolve = res;
		reject = rej;
	});
	promise.catch(() => {});
	return { promise, resolve, reject };
}

interface Link {
	readonly id: number;
	readonly client: Socket;
	readonly server: Socket;
	readonly upstream: Upstream;
	role: Role | undefined;
	open: boolean;
	/** Requests sent and not yet answered, in order; each marked if sent inside a transaction. */
	readonly asked: { readonly command: Command; readonly queued: boolean }[];
	inMulti: boolean;
	holding: boolean;
	readonly waiting: Record<Direction, Buffer[]>;
	/** Frames whose delay ran out while kept: ahead of every one waiting. */
	readonly parked: Record<Direction, Buffer[]>;
	chain: Record<Direction, Promise<void>>;
	/** Frames on the chain not yet written, so a frame sent with no delay keeps behind them. */
	readonly inFlight: Record<Direction, number>;
}

interface Rule<T> {
	readonly match: Match;
	readonly done: ReturnType<typeof settleable<T>>;
}

// Each answers more than once, or not at once, to one request.
const subscriptions = new Set([
	"SUBSCRIBE",
	"PSUBSCRIBE",
	"SSUBSCRIBE",
	"UNSUBSCRIBE",
	"PUNSUBSCRIBE",
	"SUNSUBSCRIBE",
	"MONITOR",
]);
/** `CLIENT REPLY OFF` or `SKIP`: requests with no answer, which would part each answer from its request. */
const turnsAnswersOff = (command: Command) =>
	command.name === "CLIENT" &&
	command.args[0]?.toString().toUpperCase() === "REPLY" &&
	["OFF", "SKIP"].includes(command.args[1]?.toString().toUpperCase() ?? "");

/**
 * A caller's match, its predicates guarded: one that throws first gives its error to `failed`,
 * which releases whoever waits on the rule, then throws on to cut the connection.
 */
function guardedMatch(match: Match, failed: (error: Error) => void): Match {
	const guard =
		<A>(read: (a: A) => boolean) =>
		(a: A) => {
			try {
				return read(a);
			} catch (error) {
				failed(error instanceof Error ? error : new Error(String(error)));
				throw error;
			}
		};
	// Asked through the match itself, so a match whose predicates read `this` keeps it.
	return {
		request: guard((c: Command) => match.request(c)),
		succeeded: guard((r: Reply) => match.succeeded(r)),
	};
}

/**
 * A relay between an app and Redis that reads RESP2 both ways and pairs each answer with its
 * request, to cause a fault at a known point and to show that it happened.
 */
export async function startRelay(options: RelayOptions) {
	let upstream = options.upstream;
	let nextId = 1;
	const links: Link[] = [];
	const failures: string[] = [];
	const executions: Execution[] = [];
	const stalled: Record<Direction, boolean> = { up: false, down: false };
	const delays: Record<Direction, number> = { up: 0, down: 0 };
	let drops: {
		rule: Rule<Dropped>;
		resends?: (first: Command, later: Command) => boolean;
		fired?: Dropped;
		resent: Dropped[];
		ended: boolean;
	}[] = [];
	let holds: Rule<Held>[] = [];
	let observers: (Rule<Execution> & { readonly outcome: "succeeded" | "failed" })[] = [];

	const cut = (link: Link) => {
		link.open = false;
		link.client.destroy();
		link.server.destroy();
		link.waiting.up = [];
		link.waiting.down = [];
		link.parked.up = [];
		link.parked.down = [];
	};
	const fail = (link: Link | undefined, why: string) => {
		failures.push(why);
		if (link) cut(link);
	};
	const kept = (link: Link, direction: Direction) =>
		stalled[direction] || (direction === "up" && link.holding);
	const deliver = (link: Link, direction: Direction, bytes: Buffer) => {
		const to = direction === "up" ? link.server : link.client;
		const ms = delays[direction];
		if (ms === 0 && link.inFlight[direction] === 0) {
			to.write(bytes);
			return;
		}
		link.inFlight[direction]++;
		link.chain[direction] = link.chain[direction]
			.then(() => (ms > 0 ? new Promise((resolve) => setTimeout(resolve, ms)) : undefined))
			.then(() => {
				link.inFlight[direction]--;
				if (!link.open) return;
				// A stall or a hold begun while it was delayed keeps it, in order.
				if (kept(link, direction)) link.parked[direction].push(bytes);
				else to.write(bytes);
			});
	};
	const send = (link: Link, direction: Direction, bytes: Buffer) => {
		if (!link.open) return;
		if (kept(link, direction) || link.waiting[direction].length > 0)
			link.waiting[direction].push(bytes);
		else deliver(link, direction, bytes);
	};
	const flush = (link: Link) => {
		for (const direction of ["up", "down"] as const) {
			if (kept(link, direction)) continue;
			// Parked frames have had their delay and are older than any still on the chain.
			const to = direction === "up" ? link.server : link.client;
			for (const bytes of link.parked[direction]) to.write(bytes);
			const waiting = link.waiting[direction];
			link.parked[direction] = [];
			link.waiting[direction] = [];
			for (const bytes of waiting) deliver(link, direction, bytes);
		}
	};
	const matchedAny = (command: Command) =>
		drops.some((d) => !d.ended && d.rule.match.request(command)) ||
		holds.some((h) => h.match.request(command)) ||
		observers.some((o) => o.match.request(command));
	const refuseTransaction = (command: Command) => {
		const why = `a match inside a transaction is not read (${command.name})`;
		failures.push(why);
		for (const d of drops.filter((x) => !x.fired && x.rule.match.request(command)))
			d.rule.done.reject(new Error(why));
		for (const r of [...holds, ...observers].filter((x) => x.match.request(command)))
			r.done.reject(new Error(why));
		drops = drops.filter((x) => x.fired || !x.rule.match.request(command));
		holds = holds.filter((x) => !x.match.request(command));
		observers = observers.filter((x) => !x.match.request(command));
	};

	const fromClient = (link: Link, chunk: Buffer, reader: ReturnType<typeof frames>) => {
		let read: ReturnType<typeof reader.push>;
		try {
			read = reader.push(chunk);
		} catch (error) {
			return fail(link, (error as Error).message);
		}
		for (const frame of read) {
			let command: Command;
			try {
				command = commandOf(frame.value);
			} catch (error) {
				return fail(link, (error as Error).message);
			}
			if (subscriptions.has(command.name))
				return fail(link, `a subscription is not read (${command.name})`);
			if (turnsAnswersOff(command)) return fail(link, "CLIENT REPLY OFF or SKIP is not read");
			if (command.name === "HELLO" && command.args[0]?.toString() === "3")
				return fail(link, "RESP3 is not read");
			link.role = options.roleOf?.(command) ?? link.role;
			const queued = link.inMulti && command.name !== "EXEC" && command.name !== "DISCARD";
			if (queued && matchedAny(command)) refuseTransaction(command);
			if (command.name === "MULTI") link.inMulti = true;
			if (command.name === "EXEC" || command.name === "DISCARD") link.inMulti = false;
			const hold = queued ? undefined : holds.find((h) => h.match.request(command));
			if (hold && link.holding) {
				// Holds on one connection would share its release; a second is refused.
				const why = `one hold per connection: a second matched (${command.name})`;
				failures.push(why);
				holds = holds.filter((h) => h !== hold);
				hold.done.reject(new Error(why));
			} else if (hold) {
				holds = holds.filter((h) => h !== hold);
				link.holding = true;
				hold.done.resolve({
					connection: link.id,
					command,
					release: () => {
						link.holding = false;
						flush(link);
					},
				});
			}
			link.asked.push({ command, queued });
			send(link, "up", frame.bytes);
		}
	};

	const fromServer = (link: Link, chunk: Buffer, reader: ReturnType<typeof frames>) => {
		let read: ReturnType<typeof reader.push>;
		try {
			read = reader.push(chunk);
		} catch (error) {
			return fail(link, `Redis: ${(error as Error).message}`);
		}
		// Answers read with a dropped one are recorded and observed, never passed on.
		let cutHere = false;
		for (const [i, frame] of read.entries()) {
			const asked = link.asked.shift();
			if (!asked) return fail(link, "an answer to no request");
			const { command, queued } = asked;
			const at = performance.now();
			const succeededBy = (m: Match) => m.succeeded(frame.value);
			const execution = (m?: Match): Execution => ({
				connection: link.id,
				command,
				reply: frame.value,
				succeeded: m ? succeededBy(m) : false,
				at,
			});
			executions.push(execution());
			if (!queued) {
				for (const o of observers.filter((x) => x.match.request(command))) {
					if (succeededBy(o.match) === (o.outcome === "succeeded")) {
						observers = observers.filter((x) => x !== o);
						o.done.resolve(execution(o.match));
					}
				}
			}
			if (cutHere) continue;
			if (!queued) {
				const drop = drops.find(
					(d) =>
						!d.ended &&
						(d.fired
							? (d.resends?.(d.fired.command, command) ?? false)
							: d.rule.match.request(command)),
				);
				if (drop && succeededBy(drop.rule.match)) {
					const later = read.slice(i + 1);
					const collateral = link.asked.map((x, at) => ({
						command: x.command,
						answered: at < later.length,
					}));
					const dropped = { ...execution(drop.rule.match), collateral };
					cut(link);
					cutHere = true;
					if (drop.fired) drop.resent.push(dropped);
					else {
						drop.fired = dropped;
						drop.rule.done.resolve(dropped);
						if (!drop.resends) drop.ended = true;
					}
					continue;
				}
				if (drop && !drop.fired) {
					const why = `the matched answer showed no write (${command.name}), so no fault happened`;
					failures.push(why);
					drop.ended = true;
					drop.rule.done.reject(new Error(why));
				}
			}
			send(link, "down", frame.bytes);
		}
	};

	const server = createServer((client) => {
		const link: Link = {
			id: nextId++,
			client,
			server: createConnection(upstream),
			upstream,
			role: undefined,
			open: true,
			asked: [],
			inMulti: false,
			holding: false,
			waiting: { up: [], down: [] },
			parked: { up: [], down: [] },
			chain: { up: Promise.resolve(), down: Promise.resolve() },
			inFlight: { up: 0, down: 0 },
		};
		links.push(link);
		const fromApp = frames();
		const fromRedis = frames();
		// A caller's match or role that throws fails the relay and cuts the connection, never the run.
		const guarded = (read: () => void) => {
			try {
				read();
			} catch (error) {
				fail(link, error instanceof Error ? error.message : String(error));
			}
		};
		client.on("data", (chunk: Buffer) => guarded(() => fromClient(link, chunk, fromApp)));
		link.server.on("data", (chunk: Buffer) => guarded(() => fromServer(link, chunk, fromRedis)));
		for (const socket of [client, link.server]) {
			socket.on("error", () => cut(link));
			socket.on("close", () => cut(link));
		}
	});
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	const address = server.address();
	const port = typeof address === "object" && address ? address.port : 0;

	return {
		url: `redis://127.0.0.1:${port}`,
		/** Keeps the data going one way (or both) until resumed; a partition. */
		stall(direction: Direction | "both") {
			if (direction !== "down") stalled.up = true;
			if (direction !== "up") stalled.down = true;
		},
		resume() {
			stalled.up = false;
			stalled.down = false;
			for (const link of links) flush(link);
		},
		delay(ms: number, direction: Direction | "both") {
			if (direction !== "down") delays.up = ms;
			if (direction !== "up") delays.down = ms;
		},
		/** Cuts the connections named, both ways, with what waited on them. */
		reset(which: "all" | Role) {
			for (const link of links.filter((l) => l.open && (which === "all" || l.role === which)))
				cut(link);
		},
		/**
		 * Drops the first successful answer to a matched request and cuts its connection with what came
		 * behind it; with `resends`, the answers to its resends too, until ended.
		 */
		dropReplyTo(
			match: Match,
			opts: { resends?: (first: Command, later: Command) => boolean } = {},
		): Drop {
			const done = settleable<Dropped>();
			const entry = {
				rule: {
					match: guardedMatch(match, (error) => {
						entry.ended = true;
						done.reject(error);
					}),
					done,
				},
				...(opts.resends ? { resends: opts.resends } : {}),
				resent: [] as Dropped[],
				ended: false,
			};
			drops.push(entry);
			return {
				first: entry.rule.done.promise,
				resends: entry.resent,
				end: () => {
					entry.ended = true;
				},
			};
		},
		/** Keeps the next matched request, and what follows on its connection, from Redis. */
		hold(match: Match): Promise<Held> {
			const done = settleable<Held>();
			const rule: Rule<Held> = {
				match: guardedMatch(match, (error) => {
					holds = holds.filter((h) => h !== rule);
					done.reject(error);
				}),
				done,
			};
			holds.push(rule);
			return rule.done.promise;
		},
		/** The next matched request whose answer comes out as asked. */
		observe(match: Match, opts: { outcome?: "succeeded" | "failed" } = {}): Promise<Execution> {
			const done = settleable<Execution>();
			const rule = {
				match: guardedMatch(match, (error) => {
					observers = observers.filter((o) => o !== rule);
					done.reject(error);
				}),
				done,
				outcome: opts.outcome ?? "succeeded",
			};
			observers.push(rule);
			return rule.done.promise;
		},
		executions: (match: Match): readonly Execution[] =>
			executions
				.filter((e) => match.request(e.command))
				.map((e) => ({ ...e, succeeded: match.succeeded(e.reply) })),
		connections: (): readonly Connection[] =>
			links.map(({ id, role, upstream, open }) => ({ id, role, upstream, open })),
		/** Where connections opened from now on go; those open stay where they are. */
		switchUpstream(to: Upstream) {
			upstream = to;
		},
		/** Stops the relay; fails with what it could not read or what did not happen. */
		async close() {
			for (const link of links) cut(link);
			if (drops.some((d) => !d.fired && !d.ended)) failures.push("a drop asked for never happened");
			if (holds.length > 0) failures.push("a hold asked for never happened");
			for (const d of drops) d.rule.done.reject(new Error("the relay closed"));
			for (const r of [...holds, ...observers]) r.done.reject(new Error("the relay closed"));
			await new Promise<void>((resolve) => server.close(() => resolve()));
			if (failures.length > 0) throw new Error(`the fault relay failed:\n${failures.join("\n")}`);
		},
	};
}

export type Relay = Awaited<ReturnType<typeof startRelay>>;
