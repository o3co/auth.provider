import { quietRuntime } from "@mod/kernel/testing";
import type { Space } from "@mod/store";
import type { Redis } from "ioredis";
import { expect, it } from "vitest";
import { keysUnder } from "../../keys.ts";
import { redisStore, scriptsOn, serverOf } from "../../redis-store.ts";
import { redisUpkeepWith } from "../upkeep.ts";

const space: Space = { name: "kept", guarantees: [] };
const key = { space, partition: "p", name: "k" };
const never = { expiry: { kind: "never" } } as const;

/**
 * A client whose ledger write waits until the test settles it, every other script answering
 * `answer`; it records the order scripts were sent in, by whether each was the ledger's.
 */
function heldLedger(answer: object) {
	const sent: string[] = [];
	let settle: (ok: boolean) => void = () => {};
	const ledger = new Promise<boolean>((resolve) => {
		settle = resolve;
	});
	const client = {
		eval: async (_script: string, numkeys: number, ...rest: (string | number)[]) => {
			const argv = rest.slice(numkeys).map(String);
			if (argv[0] === "keep") {
				sent.push("keep");
				if (!(await ledger)) throw new Error("NOREPLICAS Not enough good replicas to write.");
				return `abc\n{"kind":"kept"}`;
			}
			sent.push(argv.at(-2)?.endsWith(":{#control}") ? `change ${argv[5] ?? ""}` : "read");
			return `abc\n${JSON.stringify(answer)}`;
		},
	} as unknown as Redis;
	const taken = { epoch: "" };
	const upkeep = redisUpkeepWith({
		run: scriptsOn(client),
		serverOf,
		confirmed: undefined,
		keys: keysUnder("t"),
		declared: [space],
		taken,
		random: quietRuntime().random,
		honours: async () => ({ kind: "verified" }),
	});
	const store = redisStore(
		client,
		{} as Redis,
		{ prefix: "t", replicationTimeoutMs: 1000, replication: undefined },
		[space],
		taken,
		upkeep.ready,
	);
	return { store, sent, settle };
}

it("sends a change whose deadline passes while the shared ledger write is pending only after it, deadline and all, and answers late as its script judges", async () => {
	const { store, sent, settle } = heldLedger({ kind: "late" });
	const answer = store.putIfAbsent(key, 1, { ...never, deadline: 1000 });
	await new Promise((resolve) => setTimeout(resolve, 20));
	expect(sent).toEqual(["keep"]);
	settle(true);
	expect(await answer).toEqual({ kind: "late" });
	expect(sent).toEqual(["keep", "change 1000"]);
});

it("answers a change unavailable and sends nothing of it where the shared ledger write fails, and tries again on the next", async () => {
	const { store, sent, settle } = heldLedger({ kind: "written", version: "v" });
	const first = store.putIfAbsent(key, 1, never);
	const second = store.putIfAbsent(key, 2, never);
	settle(false);
	await expect(first).rejects.toMatchObject({ name: "Unavailable" });
	await expect(second).rejects.toMatchObject({ name: "Unavailable" });
	expect(sent).toEqual(["keep"]);
	await expect(store.putIfAbsent(key, 3, never)).rejects.toMatchObject({ name: "Unavailable" });
	expect(sent).toEqual(["keep", "keep"]);
});
