import { assemble, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import {
	challengeStore,
	passkeyStore,
	type StoredChallenge,
	type StoredPasskey,
} from "@mod/passkeys";
import { challengeStoreContract, passkeyStoreContract } from "@mod/passkeys/testing";
import { simulatedStore } from "@mod/store/testing";
import { expect, it } from "vitest";
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

it("keeps passkeys in the spaces webauthn's records were kept in, so the passkeys kept before read as they were", async () => {
	const { simulated, app } = await opened();
	const reached: string[] = [];
	for (const space of [
		"webauthn-store.credentials",
		"webauthn-store.subjects",
		"webauthn-store.challenges",
	]) {
		simulated.beforeNext("putIfAbsent", space, async () => {
			reached.push(space);
		});
	}
	const record = { v: 1 } as unknown as StoredPasskey;
	await app.get(passkeyStore).credentials.save("c-1", record, "endless");
	await app.get(passkeyStore).subjects.save("s-1", record, "endless");
	const challenge = Buffer.alloc(32, 7).toString("base64url");
	await app.get(challengeStore).open(challenge, record as unknown as StoredChallenge, 60_000);
	expect(reached).toEqual([
		"webauthn-store.credentials",
		"webauthn-store.subjects",
		"webauthn-store.challenges",
	]);
});
