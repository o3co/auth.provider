import {
	assemble,
	BootRefused,
	type BuildContext,
	contract,
	defineModule,
	kernelConfig,
} from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import {
	challengeStore,
	challengeStoreNeeds,
	passkeyStore,
	registrationChallengeStore,
	type StoredChallenge,
	type StoredPasskey,
} from "@mod/passkeys";
import {
	challengeStoreContract,
	passkeyStoreContract,
	registrationChallengeStoreContract,
} from "@mod/passkeys/testing";
import { type Space, type Store, spaces, store } from "@mod/store";
import { simulatedStore } from "@mod/store/testing";
import { expect, it } from "vitest";
import wiring from "../src/module.ts";

const runtime = quietRuntime({ clock: { now: () => 1_800_000_000_000 } });
const signal = new AbortController().signal;
const declared = contract<readonly Space[]>("declared-spaces");

/** The wiring on a simulated replicated store at a phase, with the build context to read readiness. */
async function opened(phase: "reader" | "indexed" = "reader", blip = false) {
	const simulated = simulatedStore();
	if (phase === "indexed") simulated.mark("subject-records.phase", "indexed");
	simulated.unreachable(blip);
	let context: BuildContext<unknown> | undefined;
	const asker = defineModule({ name: "asker", replicaSafe: false, takes: [] }, (m) => [
		m.provide(contract<object>("asker")).by((c) => {
			context = c;
			return {};
		}),
	]);
	const app = await assemble({
		modules: [simulated.module, wiring, asker],
		config: kernelConfig(),
		runtime,
	});
	const ready = () => context?.readinessReport(1000).then((r) => r.answer);
	return { simulated, app, ready, raceNextBatch: racing(simulated) };
}

/**
 * One race at a time, run before the next batch, across or within one partition, whichever of the
 * two spaces it starts with: a batch is told by its first key's space. Each hook is armed once and
 * shared, so one left armed by an earlier race runs the next race, never a stale one.
 */
function racing(simulated: ReturnType<typeof simulatedStore>) {
	let pending: (() => Promise<void>) | undefined;
	const armed = new Set<string>();
	const dispatch = (hook: string) => async () => {
		armed.delete(hook);
		const race = pending;
		pending = undefined;
		await race?.();
	};
	return (race: () => Promise<void>) => {
		pending = race;
		for (const space of ["webauthn-store.credentials", "webauthn-store.subjects"]) {
			for (const operation of ["batch", "batchAcross"] as const) {
				const hook = `${operation} ${space}`;
				if (armed.has(hook)) continue;
				armed.add(hook);
				simulated.beforeNext(operation, space, dispatch(hook));
			}
		}
	};
}

for (const phase of ["reader", "indexed"] as const) {
	// A write in indexed records watches its subject's tombstone, or lists it: a batch across.
	const written = phase === "indexed" ? "batchAcross" : "batch";
	const on = `webauthn-store on subject-records, ${phase}, on a simulated replicated store`;
	passkeyStoreContract(on, async () => {
		const { simulated, app, raceNextBatch } = await opened(phase);
		const passkeys = app.get(passkeyStore);
		return {
			passkeys,
			advance: (ms) => simulated.shiftClock(ms),
			raceNextUpdate: (key, change) =>
				simulated.beforeNext(written, "webauthn-store.subjects", async () => {
					await passkeys.subjects.update(key, (record) => ({ value: change(record) }));
				}),
			duringNextSave: (during) =>
				simulated.beforeConfirm(written, "webauthn-store.credentials", during),
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
	registrationChallengeStoreContract(on, async () => {
		const { simulated, app } = await opened(phase);
		return {
			registrations: app.get(registrationChallengeStore),
			advance: (ms) => simulated.shiftClock(ms),
			loseNextAnswer: () => simulated.loseNextReply(),
			failover: () => simulated.failover(),
			restart: () => simulated.restart(),
			holds: (text) => simulated.holds(text),
		};
	});
}

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

it("declares the passkeys indexed and the registration challenges bounded at the time passkeys keeps one, erased by passkeys; assertion challenges hold no subject's data", async () => {
	const reader = defineModule({ name: "reader", replicaSafe: true, takes: [spaces] }, (m) => [
		m.provide(declared).by(async (c) => c.collect(spaces)),
	]);
	const app = await assemble({
		modules: [simulatedStore().module, wiring, reader],
		config: kernelConfig(),
		runtime,
	});
	const named = Object.fromEntries(app.get(declared).map((s) => [s.name, s]));
	for (const name of ["webauthn-store.credentials", "webauthn-store.subjects"]) {
		expect(named[name]).toMatchObject({ subjectData: "online-indexed", erasedBy: "passkeys" });
	}
	expect(named["webauthn-store.registration-challenges"]).toMatchObject({
		subjectData: "bounded",
		boundedMs: challengeStoreNeeds.registrationsEndWithinMs,
		erasedBy: "passkeys",
	});
	expect(named["webauthn-store.challenges"]).toMatchObject({ subjectData: "none" });
	expect(named["webauthn-store.challenges"]?.erasedBy).toBeUndefined();
});

it("keeps passkeys and assertion challenges in the spaces webauthn's records were kept in, so those kept before read as they were", async () => {
	const { simulated, app } = await opened();
	const reached: string[] = [];
	for (const [operation, space] of [
		["batch", "webauthn-store.credentials"],
		["batch", "webauthn-store.subjects"],
		["putIfAbsent", "webauthn-store.challenges"],
	] as const) {
		simulated.beforeNext(operation, space, async () => {
			reached.push(space);
		});
	}
	const record = { v: 1 } as unknown as StoredPasskey;
	await app.get(passkeyStore).credentials.save("c-1", record, "endless", "alice");
	await app.get(passkeyStore).subjects.save("s-1", record, "endless", "alice");
	const challenge = Buffer.alloc(32, 7).toString("base64url");
	await app.get(challengeStore).open(challenge, record as unknown as StoredChallenge, 60_000);
	expect(reached).toEqual([
		"webauthn-store.credentials",
		"webauthn-store.subjects",
		"webauthn-store.challenges",
	]);
});

it("changes a credential and a holder as one batch across both spaces, keeping what it creates without end", async () => {
	const { simulated, app } = await opened("indexed");
	const passkeys = app.get(passkeyStore);
	const batches: string[] = [];
	for (const space of ["webauthn-store.credentials", "webauthn-store.subjects"]) {
		simulated.beforeNext("batchAcross", space, async () => {
			batches.push(space);
		});
	}
	const record = { v: 1 } as unknown as StoredPasskey;
	const create = {
		kind: "create",
		value: record,
		lifetimeMs: "endless",
		subject: "alice",
	} as const;
	const answer = await passkeys.updateAsOne?.({
		targets: [
			{ place: "credentials", key: "c-2" },
			{ place: "subjects", key: "s-2" },
		],
		decide: () => ({ targets: [create, create] }),
	});
	expect(answer).toMatchObject({ kind: "written" });
	// One batch, reaching both spaces: the first hook of either space runs before it.
	expect(batches.length).toBe(1);
	simulated.shiftClock(10 * 365 * 86_400_000);
	await simulated.restart();
	expect([await passkeys.credentials.read("c-2"), await passkeys.subjects.read("s-2")]).toEqual([
		record,
		record,
	]);
});

it("erases a subject's credentials and holder and fences its registration challenges, leaving another's", async () => {
	const { app } = await opened("indexed");
	const passkeys = app.get(passkeyStore);
	const registrations = app.get(registrationChallengeStore);
	const record = (n: number) => ({ n }) as unknown as StoredPasskey;
	await passkeys.credentials.save("c-a", record(1), "endless", "alice");
	await passkeys.subjects.save("s-a", record(1), "endless", "alice");
	await passkeys.credentials.save("c-b", record(2), "endless", "bob");
	for (const space of [passkeys.credentials, passkeys.subjects]) {
		expect(await space.erase?.("alice", signal)).toMatchObject({ kind: "erased", removed: 1 });
	}
	expect(await registrations.erase?.("alice", signal)).toMatchObject({ kind: "fenced" });
	expect([await passkeys.credentials.read("c-a"), await passkeys.subjects.read("s-a")]).toEqual([
		undefined,
		undefined,
	]);
	expect(await passkeys.credentials.save("c-a2", record(3), "endless", "alice")).toBe("erased");
	const challenge = Buffer.alloc(32, 9).toString("base64url");
	expect(await registrations.open(challenge, {} as StoredChallenge, 60_000, "alice")).toBe(
		"erased",
	);
	expect(await passkeys.credentials.read("c-b")).toEqual(record(2));
});

it("starts over a store's blip unready, out of traffic, and turns ready once the store answers", async () => {
	const { simulated, ready } = await opened("indexed", true);
	expect(await ready()).toBe("unready");
	simulated.unreachable(false);
	expect(await ready()).toBe("ready");
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
	expect((refused as BootRefused).refusals).toContainEqual({
		where: "webauthn-store",
		reason: "its store writes no records of two partitions as one",
	});
});
