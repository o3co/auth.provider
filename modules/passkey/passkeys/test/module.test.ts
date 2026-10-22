import { auditStandIn } from "@mod/audit/testing";
import { assemble, BootRefused, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import webauthn from "@mod/webauthn/module";
import {
	type CreationOptions,
	softwareAuthenticator,
	testOrigin,
	webauthnConfig,
} from "@mod/webauthn/testing";
import { expect, it } from "vitest";
import { passkeyHolders, registrations } from "../src/contract.ts";
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
