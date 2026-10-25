import { execFileSync } from "node:child_process";
import { afterAll, afterEach, describe, expect, it } from "vitest";
import { ask, askAll, microsOf } from "../../ask/ask.ts";
import { type Reply, startRelay } from "../../relay/relay.ts";
import { encode, rawClient } from "../../relay/test/client.ts";
import { roleOf } from "../../store-wire/store-wire.ts";
import { type Node, startTopology, type Topology } from "../topology.ts";

// Every topology a test starts is stopped after it, however many it starts.
let running: Topology[] = [];
afterEach(async () => {
	for (const t of running) await t.stop();
	running = [];
});
afterAll(() => {
	const left = execFileSync(
		"docker",
		["ps", "-aq", "--filter", `label=conformance.owner=${process.pid}`],
		{ encoding: "utf8" },
	).trim();
	expect(left).toBe("");
});
const topology = async (spec: Parameters<typeof startTopology>[0]) => {
	const t = await startTopology(spec);
	running.push(t);
	return t;
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
/** A write and a WAIT on one connection: WAIT counts only its own connection's writes. */
const written = async (node: Node, key: string, value: string, replicas: number) => {
	const [, acked] = await askAll(node.upstream(), [
		["SET", key, value],
		["WAIT", String(replicas), "5000"],
	]);
	return acked ? text(acked) : "";
};
const linkOf = async (node: Node) => {
	const info = await say(node, "INFO", "replication");
	return { host: field(info, "master_host"), up: field(info, "master_link_status") === "up" };
};
const exists = (what: "container" | "network" | "volume", name: string) => {
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
		expect(await written(t.primary(), "k", "v", 2)).toBe("2");
		for (const r of t.replicas()) expect(await say(r, "GET", "k")).toBe("v");
	});

	it("removes its containers and network when stopped", async () => {
		const t = await topology({ replicas: 1 });
		const names = t.nodes.map((n) => n.name);
		const volumes = names.flatMap((n) =>
			execFileSync("docker", ["inspect", "-f", "{{range .Mounts}}{{.Name}} {{end}}", n], {
				encoding: "utf8",
			})
				.trim()
				.split(" ")
				.filter(Boolean),
		);
		expect(volumes.length).toBeGreaterThan(0);
		expect(names.every((n) => exists("container", n))).toBe(true);
		expect(exists("network", t.network)).toBe(true);
		await t.stop();
		expect(names.some((n) => exists("container", n))).toBe(false);
		expect(exists("network", t.network)).toBe(false);
		expect(volumes.some((v) => exists("volume", v))).toBe(false);
	});

	it("leaves nothing behind where a start fails", async () => {
		const before = execFileSync(
			"docker",
			["network", "ls", "-q", "--filter", `label=conformance.owner=${process.pid}`],
			{ encoding: "utf8" },
		).trim();
		await expect(
			startTopology({ replicas: 1, settings: ["--no-such-setting", "x"] }),
		).rejects.toThrow();
		const after = execFileSync(
			"docker",
			["network", "ls", "-q", "--filter", `label=conformance.owner=${process.pid}`],
			{ encoding: "utf8" },
		).trim();
		expect(after).toBe(before);
		const left = execFileSync(
			"docker",
			["ps", "-aq", "--filter", `label=conformance.owner=${process.pid}`],
			{ encoding: "utf8" },
		).trim();
		expect(left).toBe("");
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
		expect(await written(old, "k", "v", 2)).toBe("2");
		await t.promote({ replica: next, reattach: [other] });
		expect(t.primary().name).toBe(next.name);
		expect(await role(next)).toBe("master");
		expect(await say(next, "GET", "k")).toBe("v");
		expect(await written(next, "k2", "v2", 1)).toBe("1");
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
			expect(await written(p, "k", "v", 1)).toBe("1");
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

describe("what a topology keeps true across its faults", () => {
	it("starts a crashed node again in its current role, following its current primary", async () => {
		const t = await topology({ replicas: 2 });
		const [next, other] = t.replicas();
		if (!next || !other) throw new Error("no replicas");
		await t.promote({ replica: next, reattach: [other] });
		await t.crash(next);
		expect(await role(next)).toBe("master");
		await t.crash(other);
		expect(await linkOf(other)).toEqual({ host: next.name, up: true });
		expect(await written(next, "k", "v", 1)).toBe("1");
	});

	it("names as replicas only the nodes following the current primary", async () => {
		const t = await topology({ replicas: 3 });
		const [stays, next, moved] = t.replicas();
		if (!stays || !next || !moved) throw new Error("no replicas");
		await t.promote({ replica: next, reattach: [moved], keepOld: true });
		expect(t.replicas().map((n) => n.name)).toEqual([moved.name]);
		const k = await topology({ replicas: 2 });
		const [a, b] = k.replicas();
		if (!a || !b) throw new Error("no replicas");
		await k.promote({ replica: a, reattach: [b] });
		expect(k.replicas().map((n) => n.name)).toEqual([b.name]);
		await k.stop();
	});

	it("refuses to keep the old primary on where none of its replicas would stay with it, changing nothing", async () => {
		const t = await topology({ replicas: 2 });
		const [next, other] = t.replicas();
		if (!next || !other) throw new Error("no replicas");
		const old = t.primary();
		await expect(t.promote({ replica: next, reattach: [other], keepOld: true })).rejects.toThrow(
			/old primary/,
		);
		expect(t.primary().name).toBe(old.name);
		expect(await role(next)).toBe("slave");
		expect(await written(old, "k", "v", 2)).toBe("2");
	});

	it("lets the old primary take writes again where a promotion keeping it on fails", async () => {
		const t = await topology({ replicas: 3 });
		const [, next, moved] = t.replicas();
		if (!next || !moved) throw new Error("no replicas");
		const old = t.primary();
		t.pause(moved, true);
		await expect(t.promote({ replica: next, reattach: [moved], keepOld: true })).rejects.toThrow();
		t.pause(moved, false);
		const taken = await ask(old.upstream(), ["SET", "after", "1"], 1_000);
		expect(taken).toEqual({ kind: "simple", text: "OK" });
	});

	it("refuses to keep the old primary on without a replica for the new one", async () => {
		const t = await topology({ replicas: 2 });
		const [next] = t.replicas();
		if (!next) throw new Error("no replica");
		await expect(t.promote({ replica: next, keepOld: true })).rejects.toThrow(/replica/);
	});

	it("refuses a replica of another replication history, whatever its offset", async () => {
		const t = await topology({ replicas: 3 });
		const [stays, next, moved] = t.replicas();
		if (!stays || !next || !moved) throw new Error("no replicas");
		const old = t.primary();
		await t.promote({ replica: next, reattach: [moved], keepOld: true });
		// The old primary goes on writing, so the replica left with it runs ahead in offset.
		for (let i = 0; i < 50; i++) await written(old, `old-${i}`, "x".repeat(1_000), 1);
		await expect(t.promote({ replica: stays, catchUpMs: 1_000 })).rejects.toThrow(/history/);
	});

	it("fails a promotion whose step outlasts the barrier, before the old primary goes, its writes free again", async () => {
		const t = await topology({ replicas: 2 });
		const [next, other] = t.replicas();
		if (!next || !other) throw new Error("no replicas");
		const old = t.primary();
		await expect(
			t.promote({
				replica: next,
				reattach: [other],
				catchUpMs: 1_000,
				holdMs: 1_500,
				between: () => new Promise((resolve) => setTimeout(resolve, 3_000)),
			}),
		).rejects.toThrow(/barrier/);
		expect(old.state().running).toBe(true);
		expect(t.primary().name).toBe(old.name);
		expect(await role(next)).toBe("slave");
		expect(await ask(old.upstream(), ["SET", "after", "1"], 1_000)).toEqual({
			kind: "simple",
			text: "OK",
		});
	});

	it("fails a promotion keeping the old primary on whose candidate detaches only after the hold lapsed", async () => {
		const t = await topology({ replicas: 3 });
		const [, next, moved] = t.replicas();
		if (!next || !moved) throw new Error("no replicas");
		let unpause: NodeJS.Timeout | undefined;
		await expect(
			t.promote({
				replica: next,
				reattach: [moved],
				keepOld: true,
				catchUpMs: 1_000,
				holdMs: 1_500,
				// The candidate stops before it is told to detach, and wakes past the hold.
				between: async () => {
					t.pause(next, true);
					unpause = setTimeout(() => t.pause(next, false), 3_000);
				},
			}),
		).rejects.toThrow(/barrier/);
		clearTimeout(unpause);
	});

	it("leaves no timer running where the scene's step fails", async () => {
		const t = await topology({ replicas: 2 });
		const [next, other] = t.replicas();
		if (!next || !other) throw new Error("no replicas");
		const timers = () => process.getActiveResourcesInfo().filter((r) => r === "Timeout").length;
		const before = timers();
		await expect(
			t.promote({
				replica: next,
				reattach: [other],
				between: () => Promise.reject(new Error("the scene's check failed")),
			}),
		).rejects.toThrow(/scene's check failed/);
		expect(timers()).toBeLessThanOrEqual(before);
	});

	it("takes no write on the old primary from its barrier until the promotion ends", async () => {
		const t = await topology({ replicas: 2 });
		const [next, other] = t.replicas();
		if (!next || !other) throw new Error("no replicas");
		const old = t.primary();
		expect(await written(old, "before", "1", 2)).toBe("2");
		let late: Reply | "unanswered" = "unanswered";
		await t.promote({
			replica: next,
			reattach: [other],
			// Sent once the target is taken: it must wait, never be taken and then lost.
			between: async () => {
				late = await ask(old.upstream(), ["SET", "late", "1"], 500).catch(
					() => "unanswered" as const,
				);
			},
		});
		expect(late).toBe("unanswered");
		expect(await say(next, "GET", "before")).toBe("1");
		expect(await say(next, "GET", "late")).toBe("");
	});
});
