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
import { passkeyWitnessStandIn as witnessStandIn } from "@mod/passkey-witness/testing";
import webauthn from "@mod/webauthn/module";
import {
	type CreationOptions,
	type RequestOptions,
	softwareAuthenticator,
	testOrigin,
	webauthnConfig,
} from "@mod/webauthn/testing";
import { expect, it } from "vitest";
import {
	challengeStore,
	type PasskeyWitnessing,
	passkeyHolders,
	passkeyStore,
	passkeys,
	passkeyWitnessing,
	registrations,
} from "../src/contract.ts";
import passkeysModule from "../src/module.ts";
import type { PasskeyStore } from "../src/store.ts";
import { passkeysConfig } from "../src/testing.ts";
import { memoryStores } from "./stores.ts";

/** A witnessing in place of passkey-witnessing's, its marks in a map: set where the subject holds a passkey, gone where an emptying write left none. */
const scriptedWitnessing = (name = "witnessing") => {
	const marks = new Map<string, string>();
	const failing = { settle: 0 };
	let n = 0;
	const witnessing: PasskeyWitnessing = {
		settle: async (subject, _at, holds) => {
			if (failing.settle > 0) {
				failing.settle -= 1;
				throw new Unavailable("passkey-witness");
			}
			const held = await holds();
			if (held && !marks.has(subject)) marks.set(subject, `m${++n}`);
			return held;
		},
		emptied: async (subject, _at, after) => {
			if ((await after()) === "none") marks.delete(subject);
		},
	};
	const module = defineModule({ name }, (m) => [
		m.contribute(passkeyWitnessing).by(() => witnessing),
	]);
	return { module, marks, failing };
};

const boot = (witnesses: { readonly module: ReturnType<typeof defineModule> }[]) =>
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

it("refuses to boot a passkey store that cannot change both its spaces as one", async () => {
	const stores = memoryStores();
	// Built where no type is checked: the type requires `updateTogether`, so boot checks it too.
	const lacking = {
		credentials: stores.passkeys.credentials,
		subjects: stores.passkeys.subjects,
	} as unknown as PasskeyStore;
	const apart = defineModule({ name: "stores-apart" }, (m) => [
		m.provide(passkeyStore).by(() => lacking),
		m.provide(challengeStore).by(() => stores.challenges),
	]);
	const refused = await assemble({
		modules: [apart, auditStandIn().module, webauthn, passkeysModule],
		config: { ...kernelConfig(), ...webauthnConfig(), ...passkeysConfig() },
		runtime: quietRuntime(),
	}).catch((error: unknown) => error);
	expect(refused).toBeInstanceOf(BootRefused);
	expect((refused as BootRefused).refusals).toEqual([
		expect.objectContaining({ where: "passkeys", reason: expect.stringMatching(/as one/) }),
	]);
});

it("refuses to boot a passkey witness composed without a witnessing to ask it", async () => {
	const refused = await boot([witnessStandIn()]).catch((error: unknown) => error);
	expect((refused as BootRefused).refusals).toContainEqual({
		where: "passkeys",
		reason: "a passkey witness is composed without passkey-witnessing",
	});
});

it("marks a subject with the witness composed once a registration is written, and clears it with the last removal", async () => {
	const stand = scriptedWitnessing();
	const app = await boot([stand]);
	const holders = app.get(passkeyHolders);
	expect(holders.witnessed).toBe(true);
	const kept = app.get(registrations);
	const options = (await kept.creation("sam")).options as CreationOptions;
	const response = softwareAuthenticator().create(options, { origin: testOrigin });
	expect(await kept.register("sam", response)).toMatchObject({ kind: "registered" });
	expect(stand.marks.has("sam")).toBe(true);
	expect(await holders.held("sam")).toBe(true);
	expect(await kept.removed("sam", response.id)).toEqual({ removed: true, empty: true });
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
	const stand = scriptedWitnessing();
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
	const stand = scriptedWitnessing();
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
	const stand = scriptedWitnessing();
	const app = await boot([stand]);
	const { kept, response } = await answered(app, "lee");
	stand.failing.settle = 1;
	await expect(kept.register("lee", response, undefined, async () => true)).rejects.toSatisfy(
		isUnavailable,
	);
	expect(await kept.listed?.("lee")).toHaveLength(1);
	await app.stop(1000);
});

it("ends a passkey whose write may have landed though its answer was lost", async () => {
	const stores = memoryStores();
	let lose = false;
	const lossy = defineModule({ name: "lossy-stores" }, (m) => [
		m.provide(passkeyStore).by(() => ({
			...stores.passkeys,
			updateTogether: async (keys, p) => {
				const done = await stores.passkeys.updateTogether(keys, p);
				if (lose) {
					lose = false;
					throw new Unavailable("passkey-store");
				}
				return done;
			},
		})),
		m.provide(challengeStore).by(() => stores.challenges),
	]);
	const stand = scriptedWitnessing();
	const app = await assemble({
		modules: [lossy, auditStandIn().module, webauthn, passkeysModule, stand.module],
		config: { ...kernelConfig(), ...webauthnConfig(), ...passkeysConfig() },
		runtime: quietRuntime(),
	});
	const { kept, response } = await answered(app, "sam");
	let asks = 0;
	const admitted = async () => {
		asks += 1;
		// The write's answer goes missing right after the first ask admits.
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
	const stand = scriptedWitnessing();
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

it("leaves no usable passkey where the registration is stopped and its end cannot be written", async () => {
	const stores = memoryStores();
	/** `lose`: the next write lands and its answer is lost; `down`: no write lands. */
	const fails = { lose: false, down: false };
	const failing = <S extends { update: (...a: never[]) => Promise<unknown> }>(store: S): S => ({
		...store,
		update: async (...args: Parameters<S["update"]>) => {
			if (fails.down) throw new Unavailable("passkey-store");
			const done = await store.update(...args);
			if (fails.lose) {
				fails.lose = false;
				fails.down = true;
				throw new Unavailable("passkey-store");
			}
			return done;
		},
	});
	const down = defineModule({ name: "failing-stores" }, (m) => [
		m.provide(passkeyStore).by(() => ({
			credentials: failing(stores.passkeys.credentials),
			subjects: failing(stores.passkeys.subjects),
			updateTogether: async (keys, p) => {
				if (fails.down) throw new Unavailable("passkey-store");
				const done = await stores.passkeys.updateTogether(keys, p);
				if (fails.lose) {
					fails.lose = false;
					fails.down = true;
					throw new Unavailable("passkey-store");
				}
				return done;
			},
		})),
		m.provide(challengeStore).by(() => stores.challenges),
	]);
	const app = await assemble({
		modules: [down, auditStandIn().module, webauthn, passkeysModule],
		config: { ...kernelConfig(), ...webauthnConfig(), ...passkeysConfig() },
		runtime: quietRuntime(),
	});
	const kept = app.get(registrations);
	const stops = {
		// The second ask says no, or fails, and the store goes down before the end is written.
		"second no": (asks: number) => {
			if (asks === 1) return true;
			fails.down = true;
			return false;
		},
		"second throws": (asks: number) => {
			if (asks === 1) return true;
			fails.down = true;
			throw new Unavailable("subject-revocation");
		},
		// The write lands, its answer is lost, and the store goes down before the end is written.
		"write lost": () => {
			fails.lose = true;
			return true;
		},
	};
	for (const [name, stop] of Object.entries(stops)) {
		Object.assign(fails, { lose: false, down: false });
		const authenticator = softwareAuthenticator();
		const options = (await kept.creation("sam")).options as CreationOptions;
		const response = authenticator.create(options, { origin: testOrigin });
		let asks = 0;
		await expect(
			kept.register("sam", response, undefined, async () => stop(++asks)),
			name,
		).rejects.toSatisfy(isUnavailable);
		fails.down = false;
		expect(await kept.listed?.("sam"), name).toEqual([]);
		const { options: asking } = await app.get(passkeys).challenge("app");
		const assertion = authenticator.get(asking as RequestOptions, { origin: testOrigin });
		expect(await app.get(passkeys).assert(assertion, "app"), name).toEqual({
			kind: "refused",
			reason: "unknown-credential",
		});
	}
	await app.stop(1000);
});

it("answers conflict where another subject takes the record over before the list, the list letting go of it", async () => {
	const app = await boot([]);
	const { kept, response } = await answered(app, "sam");
	const kims = (await kept.creation("kim")).options as CreationOptions;
	const taken = softwareAuthenticator().create(
		kims,
		{ origin: testOrigin },
		{ credentialId: response.id },
	);
	// Kim registers the same id while sam's record is written and not yet listed.
	const admitted = async () => {
		if (!(await kept.listed?.("kim"))?.length) {
			expect(await kept.register("kim", taken)).toMatchObject({ kind: "registered" });
		}
		return true;
	};
	expect(await kept.register("sam", response, undefined, admitted)).toEqual({
		kind: "refused",
		reason: "conflict",
	});
	expect(await kept.listed?.("sam")).toEqual([]);
	expect(await app.get(passkeyHolders).held("sam")).toBe(false);
	expect((await kept.listed?.("kim"))?.map((p) => p.id)).toEqual([response.id]);
	await app.stop(1000);
});

/** Two registrations of sam's for one id, each with its own key, against `app`. */
async function sameId(app: Awaited<ReturnType<typeof boot>>) {
	const kept = app.get(registrations);
	const made = async (credentialId?: string) => {
		const authenticator = softwareAuthenticator();
		const options = (await kept.creation("sam")).options as CreationOptions;
		const twist = credentialId === undefined ? {} : { credentialId };
		return {
			authenticator,
			response: authenticator.create(options, { origin: testOrigin }, twist),
		};
	};
	const one = await made();
	const two = await made(one.response.id);
	/** Whether `authenticator` signs in, as the subject it signs in as. */
	const signsIn = async ({ authenticator }: typeof one) => {
		const { options } = await app.get(passkeys).challenge("app");
		const assertion = authenticator.get(options as RequestOptions, { origin: testOrigin });
		const asserted = await app.get(passkeys).assert(assertion, "app");
		return asserted.kind === "asserted" ? asserted.subject : asserted.kind;
	};
	return { kept, one, two, signsIn };
}

it("keeps only the key of the registration both asks admitted, two of a subject's crossing on one id in either order", async () => {
	const app = await boot([]);
	// Admitted first: a revoked one asks while it does; asked before it writes, it writes nothing.
	const first = await sameId(app);
	let crossed: unknown;
	const admittedFirst = await first.kept.register(
		"sam",
		first.one.response,
		undefined,
		async () => {
			crossed ??= await first.kept.register(
				"sam",
				first.two.response,
				undefined,
				async () => false,
			);
			return true;
		},
	);
	expect([admittedFirst, crossed]).toEqual([
		expect.objectContaining({ kind: "registered" }),
		{ kind: "refused", reason: "revoked" },
	]);
	expect([await first.signsIn(first.one), await first.signsIn(first.two)]).toEqual([
		"sam",
		"refused",
	]);
	// Revoked first: the admitted one registers while it asks, and is kept alone.
	const second = await sameId(app);
	let admitted: unknown;
	const revokedFirst = await second.kept.register(
		"sam",
		second.two.response,
		undefined,
		async () => {
			admitted = await second.kept.register("sam", second.one.response);
			return false;
		},
	);
	expect([revokedFirst, admitted]).toEqual([
		{ kind: "refused", reason: "revoked" },
		expect.objectContaining({ kind: "registered" }),
	]);
	expect([await second.signsIn(second.one), await second.signsIn(second.two)]).toEqual([
		"sam",
		"refused",
	]);
	await app.stop(1000);
});

it("answers conflict for the registration listing an id another of the subject's listed first, and makes it usable for that one alone", async () => {
	const app = await boot([]);
	const { kept, one, two, signsIn } = await sameId(app);
	let listedFirst: unknown;
	const late = await kept.register("sam", one.response, undefined, async () => {
		listedFirst ??= await kept.register("sam", two.response);
		return true;
	});
	expect([late, listedFirst]).toEqual([
		{ kind: "refused", reason: "conflict" },
		expect.objectContaining({ kind: "registered" }),
	]);
	expect([await signsIn(one), await signsIn(two)]).toEqual(["refused", "sam"]);
	await app.stop(1000);
});

it("registers nothing where a removal ends the passkey between its list and its last write", async () => {
	const app = await boot([]);
	const { kept, one, signsIn } = await sameId(app);
	let asks = 0;
	const answer = await kept.register("sam", one.response, undefined, async () => {
		if (++asks === 2) await kept.removed?.("sam", one.response.id);
		return true;
	});
	expect(answer).toEqual({ kind: "refused", reason: "conflict" });
	expect(await signsIn(one)).toBe("refused");
	expect(await kept.listed?.("sam")).toEqual([]);
	await app.stop(1000);
});

it("ends only its own write where a removal and another registration of the id land during its second ask", async () => {
	const app = await boot([]);
	const { kept, one, two, signsIn } = await sameId(app);
	let asks = 0;
	let other: unknown;
	const ended = await kept.register("sam", one.response, undefined, async () => {
		if (++asks === 1) return true;
		// The id is removed while listed, and another registration writes, lists and keeps it.
		await kept.removed?.("sam", one.response.id);
		other = await kept.register("sam", two.response);
		return false;
	});
	expect([ended, other]).toEqual([
		{ kind: "refused", reason: "revoked" },
		expect.objectContaining({ kind: "registered" }),
	]);
	expect([await signsIn(one), await signsIn(two)]).toEqual(["refused", "sam"]);
	expect((await kept.listed?.("sam"))?.map((p) => p.id)).toEqual([one.response.id]);
	await app.stop(1000);
});

it("refuses to boot with two passkey witnessings contributed", async () => {
	const witnessing = (name: string) =>
		defineModule({ name }, (m) => [
			m.contribute(passkeyWitnessing).by(() => ({
				settle: async () => false,
				emptied: async () => {},
			})),
		]);
	const refused = await assemble({
		modules: [
			memoryStores().module,
			auditStandIn().module,
			webauthn,
			passkeysModule,
			witnessing("one"),
			witnessing("two"),
		],
		config: { ...kernelConfig(), ...webauthnConfig(), ...passkeysConfig() },
		runtime: quietRuntime(),
	}).catch((error: unknown) => error);
	expect((refused as BootRefused).refusals).toContainEqual({
		where: "passkeys",
		reason: "more than one passkey witnessing is contributed",
	});
});
