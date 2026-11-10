import type { Redis } from "ioredis";
import { expect, it } from "vitest";
import { honoursOf } from "../settings.ts";

const good: Record<string, string> = {
	"maxmemory-policy": "noeviction",
	appendonly: "yes",
	appendfsync: "always",
	"no-appendfsync-on-rewrite": "no",
	"min-replicas-to-write": "1",
	"min-replicas-max-lag": "10",
};

/**
 * A server that gives every guarantee: its run id told by `runIds` in turn, the last kept, its
 * replication id and evictions as `state` holds them now; it records the keys written.
 */
function server(runIds: readonly string[], state = { replid: "r1", evicted: 0 }) {
	let told = 0;
	const written: string[] = [];
	const client = {
		info: async (section: string) => {
			if (section === "server") return `run_id:${runIds[Math.min(told++, runIds.length - 1)]}\r\n`;
			if (section === "stats") return `evicted_keys:${state.evicted}\r\n`;
			return `master_replid:${state.replid}\r\nmin_slaves_good_slaves:1\r\n`;
		},
		config: async (_get: string, name: string) => [name, good[name] ?? ""],
		call: async () => ["master", 0, [["replica", "6379", "0"]]],
		set: async (key: string) => {
			written.push(key);
			return "OK";
		},
	} as unknown as Redis;
	return { client, written, state };
}

const wanted = ["no-eviction", "durable", "replicated"] as const;
const stated = { replication: "replicas" } as const;
const witnessOf = async (client: Redis) => {
	const answer = await honoursOf(client, stated, wanted, "t:{#check}:fsync");
	if (answer.kind !== "verified") throw new Error(answer.kind);
	return answer.witness;
};

it("verifies what one server gives, its reads all from it, writing the store's own key once so the check fsyncs", async () => {
	const { client, written } = server(["a"]);
	expect(await honoursOf(client, stated, wanted, "t:{#check}:fsync")).toEqual({
		kind: "verified",
		witness: expect.any(String),
	});
	expect(written).toEqual(["t:{#check}:fsync"]);
});

it("answers unavailable, never verified, where the reads may have reached another server", async () => {
	await expect(
		honoursOf(server(["a", "b"]).client, stated, wanted, "t:{#check}:fsync"),
	).rejects.toMatchObject({ name: "Unavailable" });
});

it("witnesses the same server and history alike, and otherwise apart: a restart, another history, an eviction", async () => {
	const same = server(["a"]);
	const first = await witnessOf(same.client);
	expect(await witnessOf(same.client)).toBe(first);
	expect(await witnessOf(server(["b"]).client)).not.toBe(first);
	same.state.replid = "r2";
	expect(await witnessOf(same.client)).not.toBe(first);
	same.state.replid = "r1";
	same.state.evicted = 1;
	expect(await witnessOf(same.client)).not.toBe(first);
});
