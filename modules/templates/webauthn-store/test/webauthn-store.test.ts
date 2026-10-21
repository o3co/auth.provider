import { assemble, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { challengeStore as keptChallenges, passkeyStore as keptPasskeys } from "@mod/passkeys";
import { simulatedStore } from "@mod/store/testing";
import {
	challengeStore,
	passkeyStore,
	type StoredChallenge,
	type StoredPasskey,
} from "@mod/webauthn";
import { challengeStoreContract, passkeyStoreContract } from "@mod/webauthn/testing";
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

it("keeps the records passkeys' interfaces reach in the spaces webauthn's reach, so a passkey kept before reads as it was", async () => {
	const { app } = await opened();
	const record = { v: 1, kept: "before" } as unknown as StoredPasskey;
	expect(await app.get(passkeyStore).credentials.save("c-1", record, "endless")).toBe("created");
	expect(await app.get(keptPasskeys).credentials.read("c-1")).toEqual(record);
	const mark = { v: 1, taken: false } as unknown as StoredChallenge;
	const challenge = Buffer.alloc(32, 7).toString("base64url");
	expect(await app.get(challengeStore).open(challenge, mark, 60_000)).toBe("created");
	expect((await app.get(keptChallenges).take(challenge, mark as never))?.before).toEqual(mark);
});
