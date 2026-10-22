import { auditStandIn } from "@mod/audit/testing";
import {
	assemble,
	BootRefused,
	defineModule,
	isUnavailable,
	kernelConfig,
	Unavailable,
} from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import webauthn from "@mod/webauthn/module";
import {
	type CreationOptions,
	softwareAuthenticator,
	testOrigin,
	webauthnConfig,
} from "@mod/webauthn/testing";
import { expect, it } from "vitest";
import { challengeStore, passkeyHolders, passkeyStore, registrations } from "../src/contract.ts";
import passkeysModule from "../src/module.ts";
import { passkeysConfig, passkeyWitnessStandIn } from "../src/testing.ts";
import { memoryStores } from "./stores.ts";

const boot = (witnesses: ReturnType<typeof passkeyWitnessStandIn>[]) =>
	assemble({
		modules: [
			memoryStores().module,
			auditStandIn().module,
			webauthn,
			passkeysModule,
			...witnesses.map((w) => w.module),
		],
		config: { ...kernelConfig(), ...webauthnConfig(), ...passkeysConfig() },
		runtime: quietRuntime(),
	});

it("refuses to boot with two passkey witnesses", async () => {
	await expect(
		boot([passkeyWitnessStandIn("one"), passkeyWitnessStandIn("two")]),
	).rejects.toBeInstanceOf(BootRefused);
});

it("marks a subject with the witness composed once a registration is written, and clears it with the last removal", async () => {
	const stand = passkeyWitnessStandIn();
	const app = await boot([stand]);
	const holders = app.get(passkeyHolders);
	expect(holders.witnessed).toBe(true);
	const kept = app.get(registrations);
	const options = (await kept.creation("sam")).options as CreationOptions;
	const response = softwareAuthenticator().create(options, { origin: testOrigin });
	expect(await kept.register("sam", response)).toMatchObject({ kind: "registered" });
	expect(stand.marks.has("sam")).toBe(true);
	expect(await holders.held("sam")).toBe(true);
	expect(await kept.removed?.("sam", response.id)).toEqual({ removed: true, empty: true });
	expect(stand.marks.has("sam")).toBe(false);
	await app.stop(1000);
});

/** A registration's response from `subject`'s fresh options, against `app`'s registrations. */
async function answered(app: Awaited<ReturnType<typeof boot>>, subject: string) {
	const kept = app.get(registrations);
	const options = (await kept.creation(subject)).options as CreationOptions;
	return { kept, response: softwareAuthenticator().create(options, { origin: testOrigin }) };
}

it("keeps nothing usable where the caller's check says no or fails before the passkey is listed", async () => {
	const stand = passkeyWitnessStandIn();
	const app = await boot([stand]);
	for (const admitted of [
		async () => false,
		async (): Promise<boolean> => {
			throw new Unavailable("subject-revocation");
		},
	]) {
		const { kept, response } = await answered(app, "sam");
		const answer = kept.register("sam", response, undefined, admitted);
		if ((await admitted().catch(() => "throws")) === "throws") {
			await expect(answer).rejects.toSatisfy(isUnavailable);
		} else {
			expect(await answer).toEqual({ kind: "refused", reason: "revoked" });
		}
		expect(await kept.listed?.("sam")).toEqual([]);
		expect(stand.marks.has("sam")).toBe(false);
	}
	await app.stop(1000);
});

it("ends the passkey where the check says no or fails once it is listed, its mark going too", async () => {
	const stand = passkeyWitnessStandIn();
	const app = await boot([stand]);
	for (const second of ["no", "throws"] as const) {
		const { kept, response } = await answered(app, "kim");
		let asks = 0;
		const admitted = async () => {
			asks += 1;
			if (asks === 1) return true;
			if (second === "no") return false;
			throw new Unavailable("subject-revocation");
		};
		const answer = kept.register("kim", response, undefined, admitted);
		if (second === "throws") await expect(answer, second).rejects.toSatisfy(isUnavailable);
		else expect(await answer, second).toEqual({ kind: "refused", reason: "revoked" });
		expect(asks, second).toBe(2);
		expect(await kept.listed?.("kim"), second).toEqual([]);
		expect(stand.marks.has("kim"), second).toBe(false);
	}
	await app.stop(1000);
});

it("keeps a passkey both asks admitted though the witness cannot mark it, answering unavailable", async () => {
	const stand = passkeyWitnessStandIn();
	const app = await boot([stand]);
	const { kept, response } = await answered(app, "lee");
	stand.failing.enroll = 4;
	await expect(kept.register("lee", response, undefined, async () => true)).rejects.toSatisfy(
		isUnavailable,
	);
	expect(await kept.listed?.("lee")).toHaveLength(1);
	await app.stop(1000);
});

it("ends a passkey whose listing may have landed though its answer was lost", async () => {
	const stores = memoryStores();
	let lose = false;
	const lossy = defineModule({ name: "lossy-stores" }, (m) => [
		m.provide(passkeyStore).by(() => ({
			credentials: stores.passkeys.credentials,
			subjects: {
				...stores.passkeys.subjects,
				update: async (key, change) => {
					const done = await stores.passkeys.subjects.update(key, change);
					if (lose) {
						lose = false;
						throw new Unavailable("passkey-store");
					}
					return done;
				},
			},
		})),
		m.provide(challengeStore).by(() => stores.challenges),
	]);
	const stand = passkeyWitnessStandIn();
	const app = await assemble({
		modules: [lossy, auditStandIn().module, webauthn, passkeysModule, stand.module],
		config: { ...kernelConfig(), ...webauthnConfig(), ...passkeysConfig() },
		runtime: quietRuntime(),
	});
	const { kept, response } = await answered(app, "sam");
	let asks = 0;
	const admitted = async () => {
		asks += 1;
		// The listing's answer goes missing right after the first ask admits.
		lose = true;
		return true;
	};
	await expect(kept.register("sam", response, undefined, admitted)).rejects.toSatisfy(
		isUnavailable,
	);
	expect(asks).toBe(1);
	expect(await kept.listed?.("sam")).toEqual([]);
	expect(stand.marks.has("sam")).toBe(false);
	await app.stop(1000);
});

it("ends only the new passkey where the check says no once it is listed, the subject's mark staying for the one it holds", async () => {
	const stand = passkeyWitnessStandIn();
	const app = await boot([stand]);
	const first = await answered(app, "ann");
	expect(await first.kept.register("ann", first.response)).toMatchObject({ kind: "registered" });
	const mark = stand.marks.get("ann");
	const second = await answered(app, "ann");
	let asks = 0;
	const answer = await second.kept.register(
		"ann",
		second.response,
		undefined,
		async () => ++asks === 1,
	);
	expect(answer).toEqual({ kind: "refused", reason: "revoked" });
	expect((await second.kept.listed?.("ann"))?.map((p) => p.id)).toEqual([first.response.id]);
	expect(stand.marks.get("ann")).toBe(mark);
	await app.stop(1000);
});
