import { ok, textOf } from "../ask/ask.ts";
import type { Reply } from "../relay/relay.ts";

/** A node as a promotion needs it: its name, and a command to it. */
export interface Member {
	readonly name: string;
	ask(...args: string[]): Promise<Reply>;
}

/** What a promotion reads and changes of the topology it runs in. */
export interface Membership<N extends Member> {
	readonly nodes: readonly N[];
	/** Each node's primary by name, none for a primary. */
	readonly follows: Map<string, string | undefined>;
	readonly killed: Set<string>;
	primary(): N;
	setPrimary(node: N): void;
	/** Ends the node with SIGKILL. */
	kill(node: N): void;
}

export interface PromoteOptions<N extends Member> {
	readonly replica: N;
	readonly reattach?: readonly N[];
	readonly keepOld?: boolean;
	readonly catchUpMs?: number;
	/** How long writes may be held past the catch-up, `between` included; 60 s by default. */
	readonly holdMs?: number;
	/** A step a scene takes once writes are held, before the old primary goes. */
	readonly between?: () => Promise<void>;
}

const pause = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
const field = (info: string, name: string) =>
	new RegExp(`^${name}:(.*)$`, "m").exec(info)?.[1]?.trim();
const replication = async (n: Member) => textOf(await n.ask("INFO", "replication"), ["INFO"]);
/** A command that must be done: an error answer fails the promotion. */
const done = async (n: Member, ...args: string[]) => ok(await n.ask(...args), args);
const until = async (what: string, ok: () => Promise<boolean>, ms = 10_000) => {
	const end = performance.now() + ms;
	while (!(await ok())) {
		if (performance.now() > end) throw new Error(what);
		await pause(100);
	}
};
const online = async (p: Member) =>
	(await replication(p)).split("\n").filter((l) => /^slave\d+:.*state=online/.test(l)).length;

/**
 * Promotes a replica of the topology's primary and answers the barrier's span on the base's
 * monotonic clock; refused, or failed, as the card says.
 */
export async function promote<N extends Member>(m: Membership<N>, o: PromoteOptions<N>) {
	const old = m.primary();
	const reattach = o.reattach ?? [];
	if (o.keepOld && reattach.length === 0)
		throw new Error("keeping the old primary on needs a replica reattached to the new one");
	const moving = new Set([o.replica.name, ...reattach.map((r) => r.name)]);
	const staying = m.nodes.filter(
		(n) => m.follows.get(n.name) === old.name && !m.killed.has(n.name) && !moving.has(n.name),
	);
	if (o.keepOld && staying.length === 0)
		throw new Error("keeping the old primary on needs one of its replicas to stay with it");
	// Offsets compare only within one replication history.
	const history = async (n: Member) => field(await replication(n), "master_replid");
	if ((await history(o.replica)) !== (await history(old)))
		throw new Error(
			`not eligible: ${o.replica.name} follows another replication history than ${old.name}`,
		);
	const catchUpMs = o.catchUpMs ?? 5_000;
	const held = catchUpMs + (o.holdMs ?? 60_000);
	const paused = performance.now();
	await done(old, "CLIENT", "PAUSE", String(held), "WRITE");
	const from = performance.now();
	// The pause lapses on its own: past this, the old primary may have taken writes the target
	// missed, so the promotion fails instead, a second before it can.
	const deadline = paused + held - 1_000;
	// Whatever fails from here, an old primary not killed takes writes again.
	try {
		const offset = Number(field(await replication(old), "master_repl_offset"));
		const caughtUp = async () =>
			Number(field(await replication(o.replica), "slave_repl_offset") ?? -1) >= offset;
		await until(`not eligible: ${o.replica.name} lags behind ${old.name}`, caughtUp, catchUpMs);
		if (o.between) {
			let timer: NodeJS.Timeout | undefined;
			const lapse = new Promise<void>((resolve) => {
				timer = setTimeout(resolve, Math.max(0, deadline - performance.now()));
			});
			try {
				await Promise.race([o.between(), lapse]);
			} finally {
				clearTimeout(timer);
			}
		}
		const inTime = (what: string) => {
			if (performance.now() >= deadline) throw new Error(`the barrier ran out ${what}`);
		};
		inTime(`before ${old.name} could go`);
		if (!o.keepOld) {
			m.kill(old);
			m.killed.add(old.name);
		}
		await done(o.replica, "REPLICAOF", "NO", "ONE");
		m.follows.set(o.replica.name, undefined);
		// Kept on, the old primary may take writes once the hold lapses: a candidate that detached
		// only after it is a promotion that failed, the topology needing recovery.
		if (o.keepOld) inTime(`before ${o.replica.name} detached; the topology needs recovery`);
		for (const r of reattach) {
			await done(r, "REPLICAOF", o.replica.name, "6379");
			m.follows.set(r.name, o.replica.name);
		}
		m.setPrimary(o.replica);
		await until(
			"the replicas named did not follow",
			async () => (await online(o.replica)) >= reattach.length,
		);
		if (o.keepOld) {
			await done(old, "CLIENT", "UNPAUSE");
			await until("the old primary lost every replica", async () => (await online(old)) > 0);
		}
	} catch (error) {
		if (!m.killed.has(old.name)) await old.ask("CLIENT", "UNPAUSE").catch(() => undefined);
		throw error;
	}
	return { primary: o.replica, old, barrier: { from, to: performance.now() } };
}
