import { assemble, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { simulatedStore } from "@mod/store/testing";
import { challengeStore, passkeyStore } from "@mod/webauthn";
import { challengeStoreContract, passkeyStoreContract } from "@mod/webauthn/testing";
import wiring from "../src/module.ts";

const runtime = quietRuntime({ clock: { now: () => 1_800_000_000_000 } });

const opened = async () => {
	const simulated = simulatedStore();
	const app = await assemble({
		modules: [simulated.module, wiring],
		config: kernelConfig(),
		runtime,
	});
	return { simulated, app };
};

passkeyStoreContract("webauthn-store on records, on a simulated replicated store", async () => {
	const { simulated, app } = await opened();
	const passkeys = app.get(passkeyStore);
	return {
		passkeys,
		advance: (ms) => simulated.shiftClock(ms),
		raceNextUpdate: (key, change) =>
			simulated.beforeNext("replaceIf", "webauthn-store.subjects", async () => {
				await passkeys.subjects.update(key, (record) => ({ value: change(record) }));
			}),
		duringNextSave: (during) =>
			simulated.beforeConfirm("putIfAbsent", "webauthn-store.credentials", during),
		loseNextAnswer: () => simulated.loseNextReply(),
		failover: () => simulated.failover(),
		restart: () => simulated.restart(),
		pressMemory: () => simulated.pressMemory(),
	};
});

challengeStoreContract("webauthn-store on records, on a simulated replicated store", async () => {
	const { simulated, app } = await opened();
	return {
		challenges: app.get(challengeStore),
		advance: (ms) => simulated.shiftClock(ms),
		loseNextAnswer: () => simulated.loseNextReply(),
		failover: () => simulated.failover(),
		restart: () => simulated.restart(),
		holds: (text) => simulated.holds(text),
	};
});
