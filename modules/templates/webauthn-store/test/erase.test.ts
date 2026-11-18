import { createHash } from "node:crypto";
import { type Eraser, erasers, type Walk } from "@mod/erasure-extensions";
import { assemble, contract, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import {
	passkeyStore,
	registrationChallengeStore,
	type StoredChallenge,
	type StoredPasskey,
} from "@mod/passkeys";
import passkeysModule from "@mod/passkeys/module";
import { passkeysConfig } from "@mod/passkeys/testing";
import { type Space, store, storeControl } from "@mod/store";
import { simulatedStore } from "@mod/store/testing";
import webauthn from "@mod/webauthn/module";
import { webauthnConfig } from "@mod/webauthn/testing";
import { expect, it } from "vitest";
import wiring from "../src/module.ts";

const runtime = quietRuntime({ clock: { now: () => 1_800_000_000_000 } });
const signal = new AbortController().signal;
const seen = contract<readonly Eraser[]>("webauthn-store-test.erasers");
const collecting = defineModule(
	{ name: "collecting", replicaSafe: true, takes: [erasers] },
	(m) => [m.provide(seen).by((c) => c.collect(erasers))],
);
const hashOf = (value: string) => createHash("sha256").update(value).digest("base64url");
const held = (value: object) => value as unknown as StoredPasskey;
const passkey = (subject: string) =>
	held({ v: 1, subject, publicKey: "pQ", signCount: 0, backupEligible: false, backedUp: false });
/** A holder as a node before 0.20 made it: no subject. */
const holder019 = (credentials: string[]) =>
	held({ v: 1, handle: Buffer.alloc(32, 1).toString("base64url"), credentials, fence: 0 });

it("migrates what the reader phase wrote through passkeys' eraser: a holder with no subject read through its credentials, an empty one removed, the registration challenges indexing none", async () => {
	const simulated = simulatedStore();
	const base = await assemble({
		modules: [simulated.module, wiring],
		config: kernelConfig(),
		runtime,
	});
	const shared = defineModule({ name: "store", replicaSafe: true, takes: [] }, (m) => [
		m.provide(store).by(() => base.get(store)),
		m.provide(storeControl).by(() => base.get(storeControl)),
	]);

	// Written raw, as before records were indexed: ann's passkey, her holder with no subject, cy's empty holder.
	const reader = await assemble({ modules: [shared, wiring], config: kernelConfig(), runtime });
	const raw = reader.get(passkeyStore);
	await raw.credentials.save(`c-${hashOf("id-1")}`, passkey("ann"), "endless", "ann");
	await raw.subjects.save(`s-${hashOf("ann")}`, holder019(["id-1"]), "endless", "ann");
	await raw.subjects.save(`s-${hashOf("cy")}`, holder019([]), "endless", "cy");
	const challenge = Buffer.alloc(32, 3).toString("base64url");
	await reader
		.get(registrationChallengeStore)
		.open(challenge, {} as StoredChallenge, 60_000, "ann");

	// The maintenance window marks records indexed; an instance started after it migrates.
	simulated.mark("subject-records.phase", "indexed");
	const app = await assemble({
		modules: [shared, wiring, webauthn, passkeysModule, collecting],
		config: { ...kernelConfig(), ...webauthnConfig(), ...passkeysConfig() },
		runtime,
	});
	const eraser = app.get(seen).find((e) => e.name === "passkeys");
	expect(eraser?.erasable).toBe(true);
	const inner = base.get(store);
	const walk: Walk = {
		sweep: async (space, cursor) => {
			const page = await inner.scan({ name: space, guarantees: [] } as Space, cursor);
			return page.cursor === undefined
				? { keys: page.keys, server: "one" }
				: { keys: page.keys, cursor: page.cursor, server: "one" };
		},
	};
	expect(await eraser?.migrate(walk, signal)).toEqual([
		{ kind: "migrated", space: "webauthn-store.credentials", indexed: 1, removed: 0 },
		{ kind: "migrated", space: "webauthn-store.subjects", indexed: 1, removed: 1 },
		{ kind: "migrated", space: "webauthn-store.registration-challenges", indexed: 0, removed: 0 },
	]);
	const passkeys = app.get(passkeyStore);
	expect(await passkeys.subjects.read(`s-${hashOf("cy")}`)).toBeUndefined();

	// Erasing ann finds what the migration indexed, and fences her registration challenges.
	expect((await eraser?.online("ann", signal))?.reports.map((r) => [r.space, r.kind])).toEqual([
		["webauthn-store.credentials", "erased"],
		["webauthn-store.subjects", "erased"],
		["webauthn-store.registration-challenges", "fenced"],
	]);
	expect(await passkeys.credentials.read(`c-${hashOf("id-1")}`)).toBeUndefined();
	expect(await passkeys.subjects.read(`s-${hashOf("ann")}`)).toBeUndefined();
});
