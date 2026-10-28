import { randomBytes } from "node:crypto";
import { auditStandIn } from "@mod/audit/testing";
import { assemble, defineModule, kernelConfig, type Module } from "@mod/kernel";
import { quietRuntime, unavailableSwitch } from "@mod/kernel/testing";
import { enforcers, type FactorStore, factorStore, proofSteps, type StoredFactors } from "@mod/mfa";
import mfaModule from "@mod/mfa/module";
import { type MfaSettings, mfaConfig, updatingTogether } from "@mod/mfa/testing";
import { type FactorBinding, factorBinding } from "@mod/mfa-binding";
import { factorKinds } from "@mod/mfa-extensions";
import { type FactorManaging, factorManaging } from "@mod/mfa-managing";
import { type FactorReading, factorReading } from "@mod/mfa-reading";
import { witnessStandIn } from "@mod/mfa-witness/testing";
import { memoryRecords } from "@mod/records/testing";
import sealModule from "@mod/seal/module";
import { sealConfig } from "@mod/seal/testing";
import bridge from "../src/module.ts";

/**
 * mfa beside a witness in memory and this bridge, as far as the witness is concerned: a guessable
 * counting kind `code` (the proof is the secret and a counter that must go up) and a way back
 * `backup`. A copy of mfa's own harness, cut to what the witness needs.
 */
const code = defineModule({ name: "kind-code", replicaSafe: false, takes: [] }, (m) => [
	m.contribute(factorKinds).by(() => ({
		kind: "code",
		amr: ["otp"],
		addsSecondFactor: true,
		guessable: true,
		counts: true,
		enroll: async () => {
			const secret = randomBytes(6).toString("hex");
			return { secret, show: { secret } };
		},
		verify: async (secret, state, proof) => {
			const [given, n] = proof.split(":");
			const last = typeof state === "number" ? state : -1;
			if (given !== secret) return { kind: "invalid" as const };
			return Number(n) > last
				? { kind: "valid" as const, state: Number(n) }
				: { kind: "replayed" as const };
		},
	})),
]);
const backup = defineModule({ name: "kind-backup", replicaSafe: true, takes: [] }, (m) => [
	m.contribute(factorKinds).by(() => ({
		kind: "backup",
		amr: [],
		addsSecondFactor: true,
		guessable: false,
		counts: false,
		enroll: async () => ({ secret: JSON.stringify(["b1"]), show: ["b1"] }),
		verify: async () => ({ kind: "invalid" as const }),
	})),
]);
const step = defineModule({ name: "step", replicaSafe: true, takes: [] }, (m) => [
	m.contribute(proofSteps).by(() => ({ name: "step" })),
]);
const enforcer = defineModule({ name: "enforcer", replicaSafe: true, takes: [] }, (m) => [
	m.contribute(enforcers).by(() => ({ name: "enforcer" })),
]);

/** mfa's store on the records stand-in; `wipe` loses every list, as a store wiped or rolled back would. */
function memoryFactors() {
	const fresh = () => memoryRecords<StoredFactors>(() => 0, { shards: 1, perShard: 1 });
	let stand = fresh();
	const down = unavailableSwitch<FactorStore>("factor-store");
	const store = down.wrap({
		save: (key, record) => stand.records.create(key, record, "endless"),
		read: (key) => stand.records.read(key),
		update: (key, change) => stand.records.change(key, change),
		scan: (...given: Parameters<typeof stand.records.scan>) => stand.records.scan(...given),
		updateTogether: (...given: Parameters<ReturnType<typeof updatingTogether>>) =>
			updatingTogether(stand.records)(...given),
	});
	const module = defineModule({ name: "factor-store", replicaSafe: false, takes: [] }, (m) => [
		m.provide(factorStore).by(() => store),
	]);
	return {
		module,
		down,
		/** Loses every claim on a unique value, as 0.18 left a binding whose claim was never made. */
		loseClaims: async () => {
			for (const key of (await stand.records.scan()).keys) {
				if (key.startsWith("u-")) await stand.records.remove(key);
			}
		},
		wipe: () => {
			stand = fresh();
		},
		/** Changes the next list written, as a request racing the write would. */
		raceNextChange: (write: (value: StoredFactors) => StoredFactors) => stand.raceNextChange(write),
	};
}

export async function witnessed(settings: Partial<MfaSettings> = {}, extra: Module[] = []) {
	const audit = auditStandIn();
	const place = memoryFactors();
	const witness = witnessStandIn();
	const input = {
		modules: [
			audit.module,
			place.module,
			sealModule,
			mfaModule,
			code,
			backup,
			step,
			enforcer,
			witness.module,
			bridge,
			...extra,
		],
		config: { ...kernelConfig(), ...sealConfig(), ...mfaConfig(settings) },
		runtime: quietRuntime(),
	};
	const app = await assemble(input);
	// mfa's three faces, as one for the scenes.
	const decided: FactorReading & FactorBinding & FactorManaging = {
		...app.get(factorReading),
		...app.get(factorBinding),
		...app.get(factorManaging),
	};
	const provedCode = async (subject: string) => {
		const begun = await decided.begin(subject, "code", undefined, "t");
		if (begun.kind !== "begun") throw new Error(begun.kind);
		const secret = String((begun.show as { secret: string }).secret);
		const proved = await decided.provePending(subject, begun.pending, `${secret}:0`);
		if (proved.kind !== "valid") throw new Error(proved.kind);
		return { pending: begun.pending, state: proved.state, secret };
	};
	const bindCode = async (subject: string) => {
		const { pending, state, secret } = await provedCode(subject);
		const bound = await decided.bind(subject, pending, state);
		if (bound.kind !== "bound") throw new Error(bound.kind);
		if (bound.codesDue) await decided.reissue(subject, bound.fence);
		return { ...bound, secret };
	};
	const idOf = async (subject: string, kind: string) =>
		(await decided.held(subject)).find((f) => f.kind === kind)?.id ?? "";
	const counted = async (subject: string) =>
		(await decided.held(subject)).filter((f) => f.kind === "code").length;
	return {
		app,
		input,
		decided,
		provedCode,
		bindCode,
		idOf,
		counted,
		place,
		witness,
		wipe: place.wipe,
		events: audit.events,
	};
}
