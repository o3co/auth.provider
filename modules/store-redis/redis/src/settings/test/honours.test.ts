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

/** A server that gives every guarantee, whose run id is told by `runIds` in turn, the last kept. */
function server(runIds: readonly string[]) {
	let told = 0;
	return {
		info: async (section: string) =>
			section === "server"
				? `run_id:${runIds[Math.min(told++, runIds.length - 1)]}\r\n`
				: "master_replid:r1\r\nmin_slaves_good_slaves:1\r\n",
		config: async (_get: string, name: string) => [name, good[name] ?? ""],
		call: async () => ["master", 0, [["replica", "6379", "0"]]],
	} as unknown as Redis;
}

const wanted = ["no-eviction", "durable", "replicated"] as const;

it("verifies what one server gives, its reads all from it", async () => {
	expect(await honoursOf(server(["a"]), { replication: "replicas" }, wanted)).toEqual({
		kind: "verified",
	});
});

it("answers unavailable, never verified, where the reads may have reached another server", async () => {
	await expect(
		honoursOf(server(["a", "b"]), { replication: "replicas" }, wanted),
	).rejects.toMatchObject({ name: "Unavailable" });
});
