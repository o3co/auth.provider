import { randomBytes } from "node:crypto";
import { auditStandIn } from "@mod/audit/testing";
import { assemble, defineModule, isUnavailable, kernelConfig, Unavailable } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { passkeyWitnessStandIn } from "@mod/passkey-witness/testing";
import { challengeStore, passkeyHolders, passkeyStore, registrations } from "@mod/passkeys";
import passkeysModule from "@mod/passkeys/module";
import { passkeysConfig } from "@mod/passkeys/testing";
import { simulatedStore } from "@mod/store/testing";
import webauthn from "@mod/webauthn/module";
import {
	type CreationOptions,
	softwareAuthenticator,
	testOrigin,
	webauthnConfig,
} from "@mod/webauthn/testing";
import webauthnStore from "@mod/webauthn-store/module";
import { afterEach, describe, expect, it } from "vitest";
import witnessingModule from "../src/module.ts";
import { lossy } from "./lossy.ts";

let stop = async () => {};
afterEach(() => stop());

/**
 * passkeys composed with this witnessing and a witness in memory, through their public contracts
 * only. `firstMarkedWith` runs once before the next `markedWith` answers, as another request landing
 * between an emptying write and its settle would; `firstWithdraw` runs once in place of the next
 * withdraw, handed that call to land.
 */
async function composed() {
	const stand = passkeyWitnessStandIn();
	const audit = auditStandIn();
	const hooks: {
		markedWith?: (() => Promise<void>) | undefined;
		withdraw?: ((land: () => Promise<void>) => Promise<void>) | undefined;
	} = {};
	const { markedWith, withdraw } = stand.witness;
	stand.witness.markedWith = async (subject) => {
		const run = hooks.markedWith;
		hooks.markedWith = undefined;
		await run?.();
		return markedWith(subject);
	};
	stand.witness.withdraw = async (subject, token) => {
		const run = hooks.withdraw;
		hooks.withdraw = undefined;
		const land = () => withdraw(subject, token);
		return run ? run(land) : land();
	};
	// The stores webauthn-store keeps over a simulated store, shown through a store that can break.
	const inner = await assemble({
		modules: [simulatedStore().module, webauthnStore],
		config: kernelConfig(),
		runtime: quietRuntime(),
	});
	const broken = lossy(inner.get(passkeyStore));
	const challenges = inner.get(challengeStore);
	const stores = defineModule({ name: "lossy-stores" }, (m) => [
		m.provide(passkeyStore).by(() => broken.store),
		m.provide(challengeStore).by(() => challenges),
	]);
	const app = await assemble({
		modules: [stores, webauthn, passkeysModule, witnessingModule, stand.module, audit.module],
		config: { ...kernelConfig(), ...webauthnConfig(), ...passkeysConfig() },
		runtime: quietRuntime(),
	});
	await app.start();
	stop = () => app.stop(1000);
	const regs = app.get(registrations);
	const holders = app.get(passkeyHolders);
	/** A registration of `subject`'s, its two asks answered by `admitted`: the answer. */
	const registering = async (subject: string, admitted?: (ask: number) => Promise<boolean>) => {
		const options = (await regs.creation(subject)).options as CreationOptions;
		const response = softwareAuthenticator().create(options, { origin: testOrigin });
		let asks = 0;
		return regs.register(subject, response, undefined, admitted && (() => admitted(++asks)));
	};
	const register = async (subject: string) => {
		const answer = await registering(subject);
		if (answer.kind !== "registered") throw new Error(`not registered: ${answer.reason}`);
		return answer.credential.id;
	};
	/** A registration written and listed, held at its second ask until `admit` lets it on. */
	const pending = async (subject: string) => {
		let reached = () => {};
		const second = new Promise<void>((resolve) => {
			reached = resolve;
		});
		let release = () => {};
		const gate = new Promise<void>((resolve) => {
			release = resolve;
		});
		const answer = registering(subject, async (ask) => {
			if (ask === 2) {
				reached();
				await gate;
			}
			return true;
		});
		await second;
		return {
			admit: async () => {
				release();
				expect((await answer).kind).toBe("registered");
			},
		};
	};
	const inconsistencies = () =>
		audit.events.filter((e) => e.kind === "passkey.enrollment_inconsistent");
	return {
		stand,
		broken,
		holders,
		regs,
		hooks,
		registering,
		register,
		pending,
		inconsistencies,
	};
}

type Composed = Awaited<ReturnType<typeof composed>>;

const inconsistent = (at: string) => [
	expect.objectContaining({ kind: "passkey.enrollment_inconsistent", attributes: { at } }),
];

/** How a call ended: answered, or what it threw. */
const ending = (call: Promise<unknown>) =>
	call.then(
		() => "answered" as const,
		(error: unknown) => (isUnavailable(error) ? ("unavailable" as const) : error),
	);

/** Each call that empties a list, through passkeys' contracts, set up with a mark beside what it empties. */
const callers: Record<
	string,
	{ at: string; setUp: (h: Composed) => Promise<() => Promise<unknown>> }
> = {
	"the last removal": {
		at: "removal",
		setUp: async (h) => {
			const id = await h.register("sam");
			return () => h.regs.removed("sam", id);
		},
	},
	"a reset": {
		at: "reset",
		setUp: async (h) => {
			await h.register("sam");
			return () => h.holders.cleared("sam");
		},
	},
	"a registration ended at its second ask, which empties the list": {
		at: "removal",
		setUp: async (h) => {
			// The passkey's mark, its passkey gone by a reset whose mark the store answer lost.
			await h.register("sam");
			const old = h.stand.marks.get("sam") ?? "";
			await h.holders.cleared("sam");
			h.stand.marks.set("sam", old);
			return () =>
				h.registering("sam", async (ask) => {
					if (ask === 1) return true;
					return false;
				});
		},
	},
};

describe.each(Object.entries(callers))("after %s", (_, { at, setUp }) => {
	it("withdraws the mark it read, none left once nothing is held", async () => {
		const h = await composed();
		const empty = await setUp(h);
		expect(h.stand.marks.has("sam")).toBe(true);
		expect(await ending(empty())).toBe("answered");
		expect(h.stand.marks.has("sam")).toBe(false);
		expect(h.inconsistencies()).toEqual([]);
	});

	it("keeps the mark a registration sets while its withdraw's answer is lost and sent again (c1a)", async () => {
		const h = await composed();
		const empty = await setUp(h);
		let t2: string | undefined;
		h.hooks.withdraw = async (land) => {
			await land();
			await h.register("sam");
			t2 = h.stand.marks.get("sam");
			throw new Unavailable("passkey-witness");
		};
		const ended = await ending(empty());
		expect(t2).toBeDefined();
		expect(h.stand.marks.get("sam")).toBe(t2);
		expect(ended).toBe("answered");
	});

	it("keeps the mark a registration sets before its first withdraw lands late (c1a)", async () => {
		const h = await composed();
		const empty = await setUp(h);
		let late: (() => Promise<void>) | undefined;
		h.hooks.withdraw = async (land) => {
			late = land;
			throw new Unavailable("passkey-witness");
		};
		const ended = await ending(empty());
		await h.register("sam");
		const t2 = h.stand.marks.get("sam");
		await late?.();
		expect(t2).toBeDefined();
		expect(h.stand.marks.get("sam")).toBe(t2);
		expect(ended).toBe("answered");
	});

	it("leaves the mark of a registration made after another call settled, once it resumes (c1b)", async () => {
		const h = await composed();
		const empty = await setUp(h);
		let t2: string | undefined;
		h.hooks.markedWith = async () => {
			await h.holders.cleared("sam");
			await h.register("sam");
			t2 = h.stand.marks.get("sam");
		};
		const ended = await ending(empty());
		expect(t2).toBeDefined();
		expect(h.stand.marks.get("sam")).toBe(t2);
		expect(ended).toBe("answered");
		expect(h.inconsistencies()).toEqual([]);
	});

	it("leaves the mark of a registration made between its reads and its withdraw (c1b)", async () => {
		const h = await composed();
		const empty = await setUp(h);
		let t2: string | undefined;
		h.hooks.withdraw = async (land) => {
			await h.holders.cleared("sam");
			await h.register("sam");
			t2 = h.stand.marks.get("sam");
			await land();
		};
		const ended = await ending(empty());
		expect(t2).toBeDefined();
		expect(h.stand.marks.get("sam")).toBe(t2);
		expect(ended).toBe("answered");
		expect(h.inconsistencies()).toEqual([]);
	});

	it("marks again for a registration that relied on the mark it withdraws (c1′)", async () => {
		const h = await composed();
		const empty = await setUp(h);
		const old = h.stand.marks.get("sam");
		h.hooks.withdraw = async (land) => {
			await h.register("sam");
			expect(h.stand.marks.get("sam")).toBe(old);
			await land();
		};
		const ended = await ending(empty());
		expect(h.stand.marks.has("sam")).toBe(true);
		expect(h.stand.marks.get("sam")).not.toBe(old);
		expect(await h.holders.held("sam")).toBe(true);
		expect(ended).toBe("answered");
	});

	it("leaves a registration pending when it withdraws unmarked, which marks once admitted (c1′)", async () => {
		const h = await composed();
		const empty = await setUp(h);
		let b: Awaited<ReturnType<Composed["pending"]>> | undefined;
		h.hooks.withdraw = async (land) => {
			b = await h.pending("sam");
			await land();
		};
		const ended = await ending(empty());
		expect(h.stand.marks.has("sam")).toBe(false);
		await b?.admit();
		expect(h.stand.marks.has("sam")).toBe(true);
		expect(ended).toBe("answered");
		expect(h.inconsistencies()).toEqual([]);
	});
	it("is unsure where a registration made meanwhile loses its record, keeping its mark (Astra)", async () => {
		const h = await composed();
		const empty = await setUp(h);
		let t2: string | undefined;
		h.hooks.markedWith = async () => {
			await h.holders.cleared("sam");
			const id = await h.register("sam");
			t2 = h.stand.marks.get("sam");
			h.broken.lose.record(id);
		};
		const ended = await ending(empty());
		expect(t2).toBeDefined();
		expect(h.stand.marks.get("sam")).toBe(t2);
		expect(h.inconsistencies()).toEqual(inconsistent(at));
		expect(ended).toBe("unavailable");
	});

	it("is unsure where the holder is lost after its write, keeping the mark", async () => {
		const h = await composed();
		const empty = await setUp(h);
		const old = h.stand.marks.get("sam");
		h.hooks.markedWith = async () => h.broken.lose.holder("sam");
		const ended = await ending(empty());
		expect(h.stand.marks.get("sam")).toBe(old);
		expect(h.inconsistencies()).toEqual(inconsistent(at));
		expect(ended).toBe("unavailable");
	});

	it("is unsure where the holder is made anew after its write, keeping the mark", async () => {
		const h = await composed();
		const empty = await setUp(h);
		const old = h.stand.marks.get("sam");
		h.hooks.markedWith = async () => {
			h.broken.lose.holder("sam");
			await h.regs.creation("sam");
		};
		const ended = await ending(empty());
		expect(h.stand.marks.get("sam")).toBe(old);
		expect(h.inconsistencies()).toEqual(inconsistent(at));
		expect(ended).toBe("unavailable");
	});

	it("is unsure where the holder goes back to its copy from before the write, keeping the mark", async () => {
		const h = await composed();
		const empty = await setUp(h);
		const old = h.stand.marks.get("sam");
		const copy = (await h.broken.holderCopy("sam")) as object;
		h.hooks.markedWith = async () => h.broken.backTo("sam", copy);
		const ended = await ending(empty());
		expect(h.stand.marks.get("sam")).toBe(old);
		expect(h.inconsistencies()).toEqual(inconsistent(at));
		expect(ended).toBe("unavailable");
	});

	it("is unsure where the holder goes back to a copy of the one lost before, its fence ahead (Astra, second)", async () => {
		const h = await composed();
		const older = {
			v: 1,
			handle: randomBytes(32).toString("base64url"),
			credentials: [],
			fence: 5,
		};
		h.broken.backTo("sam", older);
		h.broken.lose.holder("sam");
		// The repair: a reset makes the holder anew.
		await h.holders.cleared("sam");
		const empty = await setUp(h);
		let t2: string | undefined;
		h.hooks.markedWith = async () => {
			await h.holders.cleared("sam");
			await h.register("sam");
			t2 = h.stand.marks.get("sam");
			h.broken.backTo("sam", older);
		};
		const ended = await ending(empty());
		expect(t2).toBeDefined();
		expect(h.stand.marks.get("sam")).toBe(t2);
		expect(h.inconsistencies()).toEqual(inconsistent(at));
		expect(ended).toBe("unavailable");
	});
});

it("mends a subject whose store lost its passkeys and holder, the mark alone left: a reset makes the holder anew and withdraws it", async () => {
	const h = await composed();
	const id = await h.register("dee");
	expect(h.stand.marks.has("dee")).toBe(true);
	h.broken.lose.holder("dee");
	h.broken.lose.record(id);
	expect(await h.holders.cleared("dee")).toEqual({ removed: 0 });
	expect(h.stand.marks.has("dee")).toBe(false);
	expect(await h.holders.held("dee")).toBe(false);
	expect(h.inconsistencies()).toEqual([]);
});

it("records a mark beside no passkey where passkeys asks, through the witnessing, as inconsistent and unavailable", async () => {
	const h = await composed();
	h.stand.marks.set("dee", "lost");
	await expect(h.holders.held("dee")).rejects.toSatisfy(isUnavailable);
	expect(h.stand.marks.get("dee")).toBe("lost");
	expect(h.inconsistencies()).toEqual([
		expect.objectContaining({ subject: "dee", attributes: { at: "held" } }),
	]);
});

it("refuses boot without exactly one witness composed", async () => {
	const refused = await assemble({
		modules: [
			simulatedStore().module,
			webauthnStore,
			webauthn,
			passkeysModule,
			witnessingModule,
			auditStandIn().module,
		],
		config: { ...kernelConfig(), ...webauthnConfig(), ...passkeysConfig() },
		runtime: quietRuntime(),
	}).then(
		(app) => app.get(registrations),
		(error: unknown) => error,
	);
	expect((refused as { refusals?: unknown }).refusals).toContainEqual({
		where: "passkey-witnessing",
		reason: "exactly one passkey witness must be composed",
	});
});
