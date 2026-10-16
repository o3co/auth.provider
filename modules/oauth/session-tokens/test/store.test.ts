import { assemble, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { crowdingFor, memoryRecords } from "@mod/records/testing";
import {
	issuedTokensContract,
	pendingSessionsContract,
	sessionTokensInMemory,
	tokenIndexContract,
} from "../src/testing.ts";

issuedTokensContract("records stand-in", async () => {
	let now = 0;
	const size = 5;
	const sets = memoryRecords<never>(() => now, { shards: 1, perShard: 1 }).keyedSets(size);
	return {
		issued: { ...sets, size },
		advance: (ms) => {
			now += ms;
		},
	};
});

tokenIndexContract("records stand-in", async () => {
	let now = 0;
	const { records } = memoryRecords<string>(() => now, { shards: 1, perShard: 1 });
	return {
		index: { save: records.create, read: records.read },
		advance: (ms) => {
			now += ms;
		},
	};
});

/** The stand-in composed alone, on a clock the test moves. */
async function standIn(sizes: { size?: number; listed?: number } = {}) {
	let now = 0;
	const stores = sessionTokensInMemory(sizes);
	await assemble({
		modules: [stores.module],
		config: kernelConfig(),
		runtime: quietRuntime({ clock: { now: () => now } }),
	});
	return {
		...stores,
		advance: (ms: number) => {
			now += ms;
		},
	};
}

issuedTokensContract("session-tokens' stand-in", async () => {
	const { issued, advance } = await standIn({ size: 5 });
	return { issued, advance };
});

tokenIndexContract("session-tokens' stand-in", async () => {
	const { index, advance } = await standIn();
	return { index, advance };
});

pendingSessionsContract("records stand-in", async () => {
	const size = { shards: 4, perShard: 5 };
	return {
		list: memoryRecords<never>(() => 0, size).deferred,
		crowd: { limit: size.perShard, references: crowdingFor(size).jobs },
	};
});

pendingSessionsContract("session-tokens' stand-in", async () => {
	const { pending } = await standIn({ listed: 5 });
	return {
		list: pending,
		crowd: { limit: 5, references: (count) => Array.from({ length: count }, (_, i) => `c-${i}`) },
	};
});
