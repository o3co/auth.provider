import { assemble, isUnavailable, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { simulatedStore } from "@mod/store/testing";
import { boundaryStore, revocations } from "@mod/subject-revocation";
import revocationModule from "@mod/subject-revocation/module";
import { boundaryStoreContract } from "@mod/subject-revocation/testing";
import { describe, expect, it } from "vitest";
import wiring from "../src/module.ts";

const space = "subject-revocation-store.boundaries";

const runtime = quietRuntime({ clock: { now: () => 1_800_000_000_000 } });

boundaryStoreContract(
	"subject-revocation-store on records, on a simulated replicated store",
	async () => {
		const simulated = simulatedStore();
		const app = await assemble({
			modules: [simulated.module, wiring],
			config: kernelConfig(),
			runtime,
		});
		const boundaries = app.get(boundaryStore);
		return {
			boundaries,
			advance: (ms) => simulated.shiftClock(ms),
			raceNextUpdate: (subject, change) =>
				simulated.beforeNext("replaceIf", "subject-revocation-store.boundaries", async () => {
					await boundaries.update(subject, change);
				}),
			loseNextAnswer: () => simulated.loseNextReply(),
			failover: () => simulated.failover(),
			restart: () => simulated.restart(),
			pressMemory: () => simulated.pressMemory(),
		};
	},
);

describe("subject-revocation over the wiring", () => {
	const now = 1_800_000_000_000;
	async function composed() {
		const simulated = simulatedStore();
		const app = await assemble({
			modules: [simulated.module, wiring, revocationModule],
			config: kernelConfig(),
			runtime,
		});
		return { simulated, revocations: app.get(revocations) };
	}

	it("records a boundary, first and moved, as the deadline its write is sent with on the store's clock", async () => {
		const { simulated, revocations: r } = await composed();
		// The store's clock runs 2 s ahead: each write's deadline is 12 s past the host's time.
		simulated.shiftClock(2000);
		await r.record("alice");
		expect(await r.compare("alice", now + 12_999, "sessions")).toBe("revoked");
		expect(await r.compare("alice", now + 13_000, "sessions")).toBe("valid");
		simulated.shiftClock(5000);
		await r.record("alice");
		expect(await r.compare("alice", now + 17_999, "sessions")).toBe("revoked");
		expect(await r.compare("alice", now + 18_000, "sessions")).toBe("valid");
	});

	it("is unavailable for a write that lands past its deadline, recording nothing, and records when sent again", async () => {
		const { simulated, revocations: r } = await composed();
		simulated.beforeNext("putIfAbsent", space, async () => simulated.shiftClock(11_000));
		await expect(r.record("bob")).rejects.toSatisfy(isUnavailable);
		expect(await r.compare("bob", now, "sessions")).toBe("valid");
		await r.record("bob");
		expect(await r.compare("bob", now + 11_000, "sessions")).toBe("revoked");
	});
});
