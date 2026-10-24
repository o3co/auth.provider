import { assemble, contract, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { crowdingFor } from "@mod/records/testing";
import { closingList, cookieIndex, sessionStore, subjectSessions } from "@mod/session-lifecycle";
import { sessionStoreContract } from "@mod/session-lifecycle/testing";
import { type Space, spaces } from "@mod/store";
import { type SimulatedStore, simulatedStore } from "@mod/store/testing";
import { expect, it } from "vitest";
import wiring from "../src/module.ts";

// Smaller than the defaults, so a full shard is reached only if the section is read.
const closingsSize = { shards: 4, perShard: 3 };

// The kernel's clock; the simulated store's runs on it, so the listings' lifetimes and the records' run together.
let now = 1_800_000_000_000;
const runtime = quietRuntime({ clock: { now: () => now } });

/** The wiring on a simulated replicated store, with what the contract test does to the store. */
async function assembled() {
	const simulated = simulatedStore();
	const app = await assemble({
		modules: [simulated.module, wiring],
		config: {
			...kernelConfig(),
			"session-store": {
				"closing-shards": closingsSize.shards,
				"closings-per-shard": closingsSize.perShard,
			},
		},
		runtime,
	});
	return { app, simulated, ...storeSide(simulated) };
}

const storeSide = (simulated: SimulatedStore) => ({
	advance: (ms: number) => {
		now += ms;
	},
	crowd: { limit: closingsSize.perShard, handles: crowdingFor(closingsSize).jobs },
	loseNextAnswer: () => simulated.loseNextReply(),
	failover: () => simulated.failover(),
	restart: () => simulated.restart(),
	pressMemory: () => simulated.pressMemory(),
	holds: (text: string) => simulated.holds(text),
});

sessionStoreContract("session-store on records, on a simulated replicated store", async () => {
	const { app, simulated, ...side } = await assembled();
	const sessions = app.get(sessionStore);
	return {
		...side,
		sessions,
		cookies: app.get(cookieIndex),
		closings: app.get(closingList),
		subjects: app.get(subjectSessions),
		raceNextUpdate: (handle, change) =>
			simulated.beforeNext("replaceIf", "session-store.sessions", async () => {
				await sessions.update(handle, (record) => ({ value: change(record) }));
			}),
	};
});

it("confirms its reads of each subject's sessions, so a revocation never reads a list older than a login", async () => {
	const declared = contract<readonly Space[]>("declared");
	const reader = defineModule({ name: "reader", takes: [spaces] }, (m) => [
		m.provide(declared).by(async (c) => c.collect(spaces)),
	]);
	const simulated = simulatedStore();
	const app = await assemble({
		modules: [simulated.module, wiring, reader],
		config: kernelConfig(),
		runtime,
	});
	const subjects = app.get(declared).find((s) => s.name === "session-store.subjects");
	expect(subjects?.guarantees).toEqual(
		expect.arrayContaining(["no-eviction", "durable", "replicated", "confirmed-reads"]),
	);
});
