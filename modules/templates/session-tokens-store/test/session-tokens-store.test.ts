import { assemble, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { crowdingFor } from "@mod/records/testing";
import { issuedTokens, pendingSessions, tokenIndex } from "@mod/session-tokens";
import {
	issuedTokensContract,
	pendingSessionsContract,
	tokenIndexContract,
} from "@mod/session-tokens/testing";
import { simulatedStore } from "@mod/store/testing";
import { expect, it } from "vitest";
import wiring from "../src/module.ts";

// The kernel's clock; the simulated store's runs on it, shifted where a test says.
let now = 1_800_000_000_000;
const runtime = quietRuntime({ clock: { now: () => now } });

// Smaller than the defaults, so a full shard is reached only if the section is read.
const pendingSize = { shards: 4, perShard: 3 };

async function open(section?: Record<string, number>) {
	const simulated = simulatedStore();
	const app = await assemble({
		modules: [simulated.module, wiring],
		config: { ...kernelConfig(), ...(section && { "session-tokens-store": section }) },
		runtime,
	});
	return {
		simulated,
		issued: app.get(issuedTokens),
		index: app.get(tokenIndex),
		pending: () => app.get(pendingSessions),
	};
}

issuedTokensContract(
	"session-tokens-store on records, on a simulated replicated store",
	async () => {
		const { simulated, issued } = await open();
		return {
			issued,
			advance: (ms) => {
				now += ms;
			},
			loseNextAnswer: () => simulated.loseNextReply(),
			failover: () => simulated.failover(),
			restart: () => simulated.restart(),
			pressMemory: () => simulated.pressMemory(),
		};
	},
);

tokenIndexContract("session-tokens-store on records, on a simulated replicated store", async () => {
	const { simulated, index } = await open();
	return {
		index,
		advance: (ms) => {
			now += ms;
		},
		loseNextAnswer: () => simulated.loseNextReply(),
		failover: () => simulated.failover(),
		restart: () => simulated.restart(),
		pressMemory: () => simulated.pressMemory(),
	};
});

pendingSessionsContract(
	"session-tokens-store on records, on a simulated replicated store",
	async () => {
		const { simulated, pending } = await open({
			"pending-shards": pendingSize.shards,
			"pending-per-shard": pendingSize.perShard,
		});
		return {
			list: pending(),
			crowd: { limit: pendingSize.perShard, references: crowdingFor(pendingSize).jobs },
			loseNextAnswer: () => simulated.loseNextReply(),
			failover: () => simulated.failover(),
			restart: () => simulated.restart(),
			pressMemory: () => simulated.pressMemory(),
		};
	},
);

it("ends the references it keeps on the kernel's clock, whatever the store's says", async () => {
	const { simulated, issued } = await open();
	await issued.add("s", "r", 1000);
	simulated.shiftClock(-60_000);
	now += 1500;
	expect(await issued.members("s")).toEqual([]);
});

it("keeps as many references to a session as its section says, answering what it pushes out", async () => {
	const { issued } = await open({ "references-per-session": 2 });
	expect(issued.size).toBe(2);
	await issued.add("s", "a", 1000);
	await issued.add("s", "b", 2000);
	expect((await issued.add("s", "c", 3000)).pushedOut).toEqual(["a"]);
	expect((await issued.members("s")).map(({ member }) => member)).toEqual(["b", "c"]);
});
