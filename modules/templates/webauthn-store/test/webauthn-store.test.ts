import { assemble, BootRefused, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import {
	challengeStore,
	passkeyStore,
	type StoredChallenge,
	type StoredPasskey,
} from "@mod/passkeys";
import { challengeStoreContract, passkeyStoreContract } from "@mod/passkeys/testing";
import { type Store, store } from "@mod/store";
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
	return { simulated, app, raceNextBatch: racing(simulated) };
};

/**
 * One race at a time, run before the next batch across, whichever of the two spaces it starts with:
 * a batch across is told by its first key's space. Each space's hook is armed once and shared, so one
 * left armed by an earlier race runs the next race, never a stale one.
 */
function racing(simulated: ReturnType<typeof simulatedStore>) {
	let pending: (() => Promise<void>) | undefined;
	const armed = new Set<string>();
	const dispatch = (space: string) => async () => {
		armed.delete(space);
		const race = pending;
		pending = undefined;
		await race?.();
	};
	return (race: () => Promise<void>) => {
		pending = race;
		for (const space of ["webauthn-store.credentials", "webauthn-store.subjects"]) {
			if (armed.has(space)) continue;
			armed.add(space);
			simulated.beforeNext("batchAcross", space, dispatch(space));
		}
	};
}

passkeyStoreContract("webauthn-store on records, on a simulated replicated store", async () => {
	const { simulated, app, raceNextBatch } = await opened();
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
		raceNextTogether: (space, key, change) =>
			raceNextBatch(async () => {
				await passkeys[space].update(key, (record) => ({ value: change(record) }));
			}),
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

it("changes a credential and a subject as one batch across both spaces, keeping what it creates without end", async () => {
	const { simulated, app } = await opened();
	const passkeys = app.get(passkeyStore);
	const batches: string[] = [];
	for (const space of ["webauthn-store.credentials", "webauthn-store.subjects"]) {
		simulated.beforeNext("batchAcross", space, async () => {
			batches.push(space);
		});
	}
	const record = { v: 1 } as unknown as StoredPasskey;
	const changed = await passkeys.updateTogether?.(
		{ credentials: ["c-2"], subjects: ["s-2"] },
		{
			watch: () => ({}),
			change: () => ({ credentials: [{ value: record }], subjects: [{ value: record }] }),
		},
	);
	expect(changed).toEqual({
		credentials: [{ before: undefined, after: record }],
		subjects: [{ before: undefined, after: record }],
	});
	// One batch, reaching both spaces: the first hook of either space runs before it.
	expect(batches.length).toBe(1);
	simulated.shiftClock(10 * 365 * 86_400_000);
	await simulated.restart();
	expect([await passkeys.credentials.read("c-2"), await passkeys.subjects.read("s-2")]).toEqual([
		record,
		record,
	]);
});

it("refuses to start over a store that writes no records of two partitions as one", async () => {
	const lacking = defineModule({ name: "lacking-store", replicaSafe: true, takes: [] }, (m) => [
		// Refused while it is built, before any call: a store with no batch across is enough.
		m.provide(store).by(() => ({}) as Store),
	]);
	const refused = await assemble({
		modules: [lacking, wiring],
		config: kernelConfig(),
		runtime,
	}).catch((error: unknown) => error);
	expect(refused).toBeInstanceOf(BootRefused);
	expect((refused as BootRefused).refusals).toEqual([
		{ where: "webauthn-store", reason: "its store writes no records of two partitions as one" },
	]);
});

it("runs each race before the next batch across, whichever space the batch starts with, one after another", async () => {
	const { app, raceNextBatch } = await opened();
	const passkeys = app.get(passkeyStore);
	const asStored = (n: number) => ({ n }) as unknown as StoredPasskey;
	await passkeys.credentials.save("c-3", asStored(1), "endless");
	await passkeys.subjects.save("s-3", asStored(1), "endless");
	const seen: unknown[] = [];
	const look = (keys: { credentials: string[]; subjects: string[] }) =>
		passkeys.updateTogether?.(keys, {
			watch: () => ({}),
			change: (read) => {
				seen.push([...read.credentials, ...read.subjects]);
				return {};
			},
		});
	// Started by the credentials space, then by the subjects space: each race lands before its own batch.
	raceNextBatch(() =>
		passkeys.credentials.update("c-3", () => ({ value: asStored(2) })).then(() => {}),
	);
	await look({ credentials: ["c-3"], subjects: [] });
	raceNextBatch(() =>
		passkeys.subjects.update("s-3", () => ({ value: asStored(3) })).then(() => {}),
	);
	await look({ credentials: [], subjects: ["s-3"] });
	expect(seen).toEqual([[asStored(1)], [asStored(2)], [asStored(1)], [asStored(3)]]);
});
