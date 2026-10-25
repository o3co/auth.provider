import { execFileSync } from "node:child_process";
import { afterEach, describe, expect, it } from "vitest";
import { type Reply, startRelay } from "../../relay/relay.ts";
import { encode, rawClient } from "../../relay/test/client.ts";
import { roleOf } from "../../store-wire/store-wire.ts";
import { microsOf, startTopology, type Topology } from "../topology.ts";

let running: Topology | undefined;
afterEach(async () => {
	await running?.stop();
	running = undefined;
});
const topology = async (spec: Parameters<typeof startTopology>[0]) => {
	running = await startTopology(spec);
	return running;
};

/** A reply's text: a status, an error, a number, a string, or an array's lines. */
const text = (r: Reply): string =>
	r.kind === "simple" || r.kind === "error"
		? r.text
		: r.kind === "integer"
			? String(r.value)
			: r.kind === "bulk"
				? (r.data?.toString() ?? "")
				: (r.items ?? []).map(text).join("\n");
const say = async (node: { ask(...args: string[]): Promise<Reply> }, ...args: string[]) =>
	text(await node.ask(...args));
const role = async (node: { ask(...args: string[]): Promise<Reply> }) =>
	(await say(node, "ROLE")).split("\n")[0];
const field = (info: string, name: string) =>
	new RegExp(`^${name}:(.*)$`, "m").exec(info)?.[1]?.trim();
const exists = (what: "container" | "network", name: string) => {
	try {
		execFileSync("docker", [what, "inspect", name], { stdio: "ignore" });
		return true;
	} catch {
		return false;
	}
};

describe("a Redis topology", () => {
	it("starts a primary and its replicas, each at its own port, the replicas online", async () => {
		const t = await topology({ replicas: 2 });
		expect(await role(t.primary())).toBe("master");
		expect(field(await say(t.primary(), "INFO", "replication"), "connected_slaves")).toBe("2");
		expect(new Set(t.nodes.map((n) => n.upstream().port)).size).toBe(3);
		await say(t.primary(), "SET", "k", "v");
		expect(await say(t.primary(), "WAIT", "2", "5000")).toBe("2");
		for (const r of t.replicas()) expect(await say(r, "GET", "k")).toBe("v");
	});

	it("removes its containers and network when stopped", async () => {
		const t = await topology({ replicas: 1 });
		const names = t.nodes.map((n) => n.name);
		expect(names.every((n) => exists("container", n))).toBe(true);
		expect(exists("network", t.network)).toBe(true);
		await t.stop();
		running = undefined;
		expect(names.some((n) => exists("container", n))).toBe(false);
		expect(exists("network", t.network)).toBe(false);
	});
});

describe("promoting a replica", () => {
	it("refuses a replica that has not caught up with the primary", async () => {
		const t = await topology({ replicas: 2 });
		const [lagging] = t.replicas();
		if (!lagging) throw new Error("no replica");
		// Pointed at no server, it stays a replica, answers, and falls behind.
		await say(lagging, "REPLICAOF", "192.0.2.1", "6379");
		await say(t.primary(), "SET", "k", "v");
		await expect(t.promote({ replica: lagging, catchUpMs: 1_000 })).rejects.toThrow(/not eligible/);
	});

	it("promotes a caught-up replica, kills the old primary, and reattaches the replicas named", async () => {
		const t = await topology({ replicas: 2 });
		const [next, other] = t.replicas();
		if (!next || !other) throw new Error("no replicas");
		const old = t.primary();
		await say(old, "SET", "k", "v");
		await say(old, "WAIT", "2", "5000");
		await t.promote({ replica: next, reattach: [other] });
		expect(t.primary().name).toBe(next.name);
		expect(await role(next)).toBe("master");
		expect(await say(next, "GET", "k")).toBe("v");
		await say(next, "SET", "k2", "v2");
		expect(await say(next, "WAIT", "1", "5000")).toBe("1");
		expect(old.state()).toEqual({ running: false, exitCode: 137 });
	});

	it("keeps the old primary on: two primaries, each with a healthy replica", async () => {
		const t = await topology({ replicas: 3 });
		const [, next, moved] = t.replicas();
		if (!next || !moved) throw new Error("no replicas");
		const old = t.primary();
		await t.promote({ replica: next, reattach: [moved], keepOld: true });
		for (const p of [old, next]) {
			expect(await role(p)).toBe("master");
			await say(p, "SET", "k", "v");
			expect(await say(p, "WAIT", "1", "5000")).toBe("1");
		}
		expect(await old.runId()).not.toBe(await next.runId());
	});

	it("lets the relay part the operations connection from the confirming one, each seen where it goes", async () => {
		const t = await topology({ replicas: 3 });
		const [, next, moved] = t.replicas();
		if (!next || !moved) throw new Error("no replicas");
		const old = t.primary();
		const relay = await startRelay({ upstream: old.upstream(), roleOf });
		const confirming = await rawClient(relay.url);
		const operations = await rawClient(relay.url);
		confirming.write(encode("WAIT", "1", "1000"));
		operations.write(encode("EVAL", "return 1", "0"));
		await Promise.all([confirming.replies(1), operations.replies(1)]);
		await t.promote({ replica: next, reattach: [moved], keepOld: true });
		relay.switchUpstream(next.upstream());
		relay.reset("operations");
		await operations.closed;
		const again = await rawClient(relay.url);
		again.write(encode("EVAL", "return 1", "0"));
		await again.replies(1);
		const open = relay.connections().filter((c) => c.open);
		expect(open.map((c) => [c.role, c.upstream.port])).toEqual([
			["confirming", old.upstream().port],
			["operations", next.upstream().port],
		]);
		confirming.end();
		again.end();
		await relay.close();
	});
});

describe("the faults of a node", () => {
	it("crashes a node with SIGKILL and starts it again, keeping what it wrote with fsync always", async () => {
		const t = await topology({ replicas: 0 });
		const node = t.primary();
		await say(node, "SET", "k", "v");
		expect(await t.crash(node)).toEqual({ exitCode: 137 });
		expect(await say(node, "GET", "k")).toBe("v");
	});

	it("makes a node slow: a request sent while it sleeps is served only once the sleep is over", async () => {
		const t = await topology({ replicas: 0 });
		const node = t.primary();
		// The hint can come early under load: a probe Redis served before the sleep began proves
		// nothing, and the round is tried again; one served during the sleep cannot be.
		for (let round = 0; round < 5; round++) {
			const sleeping = t.sleep(node, 1);
			let over = false;
			void sleeping.awake.then(() => {
				over = true;
			});
			await sleeping.asleep;
			// A probe sent once the sleep has answered would be served after it, held or not.
			if (over) continue;
			const served = microsOf(await node.ask("TIME"));
			const { from, to } = await sleeping.awake;
			if (served < from) continue;
			expect(served).toBeGreaterThanOrEqual(to);
			return;
		}
		throw new Error("no probe was sent while the node slept");
	});

	it("starts with the settings given: a bounded memory refuses a write past it", async () => {
		const t = await topology({
			replicas: 0,
			settings: ["--maxmemory", "2mb", "--maxmemory-policy", "noeviction"],
		});
		const refused = await t.primary().ask("SET", "big", "x".repeat(3_000_000));
		expect(refused.kind === "error" && refused.text).toMatch(/^OOM/);
	});

	it("runs Redis on a clock moved by the offset given", async () => {
		const t = await topology({ replicas: 0, clock: "+2h" });
		const [seconds] = (await say(t.primary(), "TIME")).split("\n");
		const moved = Number(seconds) - Math.floor(Date.now() / 1000);
		expect(moved).toBeGreaterThan(7_190);
		expect(moved).toBeLessThan(7_210);
	});
});
