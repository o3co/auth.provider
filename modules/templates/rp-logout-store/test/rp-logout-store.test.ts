import { assemble, type BuildContext, contract, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { noticeBodies, noticeQueue, pendingNotices, sessionClients } from "@mod/rp-logout";
import {
	noticeBodiesContract,
	pendingNoticesContract,
	sessionClientsContract,
} from "@mod/rp-logout/testing";
import { simulatedStore } from "@mod/store/testing";
import { expect, it } from "vitest";
import wiring from "../src/module.ts";
import { section } from "../src/section.ts";

// The kernel's clock; the simulated store's runs on it.
let now = 1_800_000_000_000;
const runtime = quietRuntime({ clock: { now: () => now } });

async function open(settings?: Record<string, number>, phase: "reader" | "indexed" = "reader") {
	const simulated = simulatedStore();
	if (phase === "indexed") simulated.mark("subject-records.phase", "indexed");
	const app = await assemble({
		modules: [simulated.module, wiring],
		config: { ...kernelConfig(), ...(settings && { "rp-logout-store": settings }) },
		runtime,
	});
	const faults = {
		loseNextAnswer: () => simulated.loseNextReply(),
		failover: () => simulated.failover(),
		restart: () => simulated.restart(),
		pressMemory: () => simulated.pressMemory(),
	};
	return { app, faults };
}

sessionClientsContract("rp-logout-store on records, on a simulated replicated store", async () => {
	const { app, faults } = await open({ "clients-per-session": 4 });
	return {
		clients: app.get(sessionClients),
		size: 4,
		advance: (ms) => {
			now += ms;
		},
		...faults,
	};
});

pendingNoticesContract("rp-logout-store on records, on a simulated replicated store", async () => {
	const { app, faults } = await open();
	return { notices: app.get(pendingNotices), ...faults };
});

for (const phase of ["reader", "indexed"] as const) {
	noticeBodiesContract(
		`rp-logout-store on subject-records, on a simulated replicated store (${phase})`,
		async () => {
			const { app, faults } = await open(undefined, phase);
			return {
				bodies: app.get(noticeBodies),
				advance: (ms) => {
					now += ms;
				},
				...faults,
			};
		},
	);
}

// The queue goes through as the pending notices do.
pendingNoticesContract(
	"rp-logout-store's queue on records, on a simulated replicated store",
	async () => {
		const { app, faults } = await open();
		return { notices: app.get(noticeQueue), ...faults };
	},
);

it("starts over a store's blip unready, out of traffic, and turns ready once the store answers", async () => {
	const simulated = simulatedStore();
	simulated.mark("subject-records.phase", "indexed");
	simulated.unreachable(true);
	let context: BuildContext<unknown> | undefined;
	const asker = defineModule({ name: "asker", replicaSafe: false, takes: [] }, (m) => [
		m.provide(contract<object>("asker")).by((c) => {
			context = c;
			return {};
		}),
	]);
	await assemble({ modules: [simulated.module, wiring, asker], config: kernelConfig(), runtime });
	const ready = () => context?.readinessReport(1000).then((r) => r.answer);
	expect(await ready()).toBe("unready");
	simulated.unreachable(false);
	expect(await ready()).toBe("ready");
});

it("keeps 64 clients to a session, and spreads notices over 64 shards of 1,000, unless told otherwise", () => {
	expect(section.parse({})).toEqual({
		"clients-per-session": 64,
		"notice-shards": 64,
		"notices-per-shard": 1000,
	});
	for (const [name, bad] of [
		["no client to a session", { "clients-per-session": 0 }],
		["over a thousand clients", { "clients-per-session": 1001 }],
		["no shard", { "notice-shards": 0 }],
		["a shard over ten thousand", { "notices-per-shard": 10_001 }],
	] as const) {
		expect([name, section.safeParse(bad).success]).toEqual([name, false]);
	}
});
