import { type AuditRecord, audit } from "@mod/audit";
import { assemble, defineModule, kernelConfig, type Module } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { flowParts } from "@mod/mfa-flows";
import { factorManaging } from "@mod/mfa-managing";
import { factorReading } from "@mod/mfa-reading";
import { mfaReset } from "@mod/mfa-reset";
import resetModule from "@mod/mfa-reset/module";
import passkeyReset from "@mod/passkey-reset/module";
import { registrations } from "@mod/passkeys";
import passkeysModule from "@mod/passkeys/module";
import { passkeysConfig } from "@mod/passkeys/testing";
import { lockouts } from "@mod/rate-limit";
import { simulatedStore } from "@mod/store/testing";
import { revocations } from "@mod/subject-revocation";
import webauthn from "@mod/webauthn/module";
import {
	type CreationOptions,
	softwareAuthenticator,
	testOrigin,
	webauthnConfig,
} from "@mod/webauthn/testing";
import webauthnStore from "@mod/webauthn-store/module";
import { afterEach, expect, it } from "vitest";
import bridge from "../src/module.ts";

let stop = async () => {};
afterEach(() => stop());

/**
 * mfa's reset with passkeys and their reset, the factors, boundaries and lockout scripted, and the
 * bridge unless left out. What each step was asked is recorded in order; `factorsGo` runs as the
 * factors go, before any part.
 */
async function composed({ withBridge = true } = {}) {
	const store = simulatedStore();
	const steps: string[] = [];
	const events: AuditRecord[] = [];
	const hooks: {
		factorsGo?: (() => Promise<void> | void) | undefined;
		boundary?: ((n: number) => void) | undefined;
	} = {};
	let boundaries = 0;
	const base = defineModule({ name: "base" }, (m) => [
		m.provide(flowParts).by(() => ({ lockout: { name: "mfa", policy: { budget: 10 } } }) as never),
		m.provide(factorManaging).by(
			() =>
				({
					clear: async () => {
						steps.push("factors");
						await hooks.factorsGo?.();
						return { count: 1, kinds: ["code"] };
					},
				}) as never,
		),
		m.provide(revocations).by(
			() =>
				({
					record: async () => {
						boundaries += 1;
						steps.push("boundary");
						hooks.boundary?.(boundaries);
						return { complete: true };
					},
				}) as never,
		),
		m.provide(lockouts).by(
			() =>
				({
					releaseUnder: async () => {
						steps.push("lockout");
						return {};
					},
				}) as never,
		),
		m.provide(audit).by(() => ({ record: (event) => void events.push(event), lost: () => ({}) })),
		// mfa-reset reads the factors too, to tell whom to reset; nothing here asks it.
		m.provide(factorReading).by(() => ({ unclaimedWritten: async () => 0 }) as never),
	]);
	const modules: Module[] = [
		store.module,
		webauthnStore,
		webauthn,
		passkeysModule,
		base,
		resetModule,
		passkeyReset,
		...(withBridge ? [bridge] : []),
	];
	const app = await assemble({
		modules,
		config: { ...kernelConfig(), ...webauthnConfig(), ...passkeysConfig() },
		runtime: quietRuntime(),
	});
	await app.start();
	stop = () => app.stop(1000);
	const regs = app.get(registrations);
	const register = async (subject: string) => {
		const options = (await regs.creation(subject)).options as CreationOptions;
		const response = softwareAuthenticator().create(options, { origin: testOrigin });
		expect((await regs.register(subject, response)).kind).toBe("registered");
	};
	const listed = async (subject: string) => (await regs.listed(subject)).length;
	const resets = () => events.filter((e) => e.kind === "mfa.reset").map((e) => e.attributes);
	return { store, steps, hooks, register, listed, resets, reset: app.get(mfaReset) };
}

it("removes the subject's passkeys with its factors, between the boundaries and before the lockout's release", async () => {
	const h = await composed();
	await h.register("ann");
	await h.register("ann");
	let listedAsFactorsGo = -1;
	h.hooks.factorsGo = async () => {
		listedAsFactorsGo = await h.listed("ann");
	};
	expect(await h.reset.run("ann")).toEqual({
		kind: "done",
		removed: 1,
		kinds: ["code"],
		parts: { passkeys: 2 },
	});
	expect(listedAsFactorsGo).toBe(2);
	expect(await h.listed("ann")).toBe(0);
	expect(h.steps).toEqual(["boundary", "factors", "lockout", "boundary"]);
	expect(h.resets()).toEqual([expect.objectContaining({ parts: "passkeys=2", complete: "true" })]);
});

it("moves no boundary of its own: the reset's two are the only ones", async () => {
	const h = await composed();
	await h.register("ann");
	await h.reset.run("ann");
	expect(h.steps.filter((s) => s === "boundary")).toHaveLength(2);
});

it("stops the reset at the parts where the passkeys cannot be removed, the lockout kept, and finishes when run again", async () => {
	const h = await composed();
	await h.register("ann");
	// The passkey store goes away as the factors go, and comes back for the second boundary.
	h.hooks.factorsGo = () => h.store.unreachable(true);
	h.hooks.boundary = (n) => {
		if (n === 2) h.store.unreachable(false);
	};
	expect(await h.reset.run("ann")).toEqual({
		kind: "stopped",
		at: "parts",
		removed: { count: 1, kinds: ["code"] },
	});
	expect(h.steps).toEqual(["boundary", "factors", "boundary"]);
	expect(h.resets()).toEqual([
		expect.objectContaining({ partsStopped: "passkeys", complete: "false" }),
	]);
	h.hooks.factorsGo = undefined;
	h.hooks.boundary = undefined;
	expect(await h.reset.run("ann")).toMatchObject({ kind: "done", parts: { passkeys: 1 } });
	expect(await h.listed("ann")).toBe(0);
});

it("leaves passkeys as they are where the bridge is not composed, booting all the same", async () => {
	const h = await composed({ withBridge: false });
	await h.register("ann");
	expect(await h.reset.run("ann")).toEqual({
		kind: "done",
		removed: 1,
		kinds: ["code"],
		parts: {},
	});
	expect(await h.listed("ann")).toBe(1);
});
