import { randomBytes } from "node:crypto";
import { isUnavailable, Unavailable } from "@mod/kernel";
import { recordingLog } from "@mod/kernel/testing";
import {
	type CreationOptions,
	testCeremonies as ceremoniesFor,
	softwareAuthenticator,
	testOrigin,
} from "@mod/webauthn/testing";
import { describe, expect, it } from "vitest";
import { memoryStores, writeToken } from "../../../test/stores.ts";
import { keptChallenges } from "../../challenges/challenges.ts";
import { type Asked, holdersOver } from "../../holders/holders.ts";
import { type KeptPasskeys, keptPasskeys } from "../../records.ts";
import { passkeyWitnessStandIn } from "../../testing.ts";
import type { PasskeyWitness } from "../../witness.ts";
import { registrationsOver } from "../registrations.ts";

const fresh = () => randomBytes(32).toString("base64url");
type Options = CreationOptions & { excludeCredentials: { id: string }[] };

/**
 * Registrations and holdings wired as the package wires them, over memory stores and a witness in
 * memory. `paused` runs once right after the next write that empties a list answers, before its
 * settle; `firstRemoval` runs once in place of the next withdraw, handed that call to land.
 */
function wired() {
	const stores = memoryStores(() => Date.now());
	const kept = keptPasskeys(stores.passkeys, writeToken, Date.now);
	const reads = { markedWith: 0, afterRemoval: 0 };
	const state: { paused?: (() => Promise<unknown>) | undefined } = {};
	const pause = async <T extends { emptied?: unknown }>(answer: T) => {
		const run = answer.emptied === undefined ? undefined : state.paused;
		if (run) state.paused = undefined;
		await run?.();
		return answer;
	};
	const records: KeptPasskeys = {
		...kept,
		removed: async (subject, id) => pause(await kept.removed(subject, id)),
		ended: async (subject, id, written) => pause(await kept.ended(subject, id, written)),
		cleared: async (subject, handle) => pause(await kept.cleared(subject, handle)),
		afterRemoval: async (subject, emptied) => {
			reads.afterRemoval += 1;
			return kept.afterRemoval(subject, emptied);
		},
	};
	const stand = passkeyWitnessStandIn();
	const witness: PasskeyWitness = stand.witness;
	const markedWith = stand.witness.markedWith;
	witness.markedWith = async (subject) => {
		reads.markedWith += 1;
		return markedWith(subject);
	};
	let removal: ((land: () => Promise<void>) => Promise<void>) | undefined;
	const once = (land: () => Promise<void>) => {
		const run = removal;
		removal = undefined;
		return run ? run(land) : land();
	};
	const { withdraw } = witness;
	witness.withdraw = (subject, token) => once(() => withdraw(subject, token));
	const events: { kind: string; attributes?: unknown }[] = [];
	let n = 0;
	const { holders, settle } = holdersOver({
		records,
		witness,
		audit: { record: (event) => void events.push(event) },
		log: recordingLog().log,
		token: () => `t${++n}`,
		handle: fresh,
	});
	const rp = {
		id: "rp.example",
		name: "RP",
		origins: [testOrigin],
		topOrigins: [],
		timeoutMs: 120_000,
	};
	const registrations = registrationsOver({
		ceremonies: ceremoniesFor(rp, (k) => new Uint8Array(randomBytes(k)), Date.now),
		records,
		challenges: keptChallenges(stores.challenges, Date.now, 120_000),
		verification: "preferred",
		max: 10,
		freshHandle: fresh,
		settle,
	});
	/** A registration of `subject`'s, its two asks answered by `admitted`: the answer. */
	const registering = async (subject: string, admitted?: (ask: number) => Promise<boolean>) => {
		const options = (await registrations.creation(subject)).options as Options;
		const response = softwareAuthenticator().create(options, { origin: testOrigin });
		let asks = 0;
		return registrations.register(
			subject,
			response,
			undefined,
			admitted && (() => admitted(++asks)),
		);
	};
	/** A passkey registered: its id. */
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
	return {
		stores,
		records,
		stand,
		reads,
		events,
		holders,
		registrations,
		state,
		registering,
		register,
		pending,
		firstRemoval: (run: (land: () => Promise<void>) => Promise<void>) => {
			removal = run;
		},
	};
}

type Wired = ReturnType<typeof wired>;

/** How a call ended: answered, or what it threw; asked after what it must keep is checked. */
const ending = (call: Promise<unknown>) =>
	call.then(
		() => "answered" as const,
		(error: unknown) => (isUnavailable(error) ? ("unavailable" as const) : error),
	);

/** Each call that empties a list, through the package's own callers, set up with a mark beside what it empties: its call. */
const callers: Record<string, { at: Asked; setUp: (h: Wired) => Promise<() => Promise<unknown>> }> =
	{
		"the last removal": {
			at: "removal",
			setUp: async (h) => {
				const id = await h.register("sam");
				return () => h.registrations.removed("sam", id);
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
				const old = await h.register("sam");
				return () =>
					h.registering("sam", async (ask) => {
						if (ask === 1) return true;
						// The passkey went with no settle meanwhile, its mark left beside this one alone.
						await h.records.removed("sam", old);
						return false;
					});
			},
		},
	};

const inconsistent = (at: Asked) => [
	expect.objectContaining({ kind: "passkey.enrollment_inconsistent", attributes: { at } }),
];

describe.each(Object.entries(callers))("after %s", (_, { at, setUp }) => {
	it("withdraws the mark it read, none left once nothing is held", async () => {
		const h = wired();
		const empty = await setUp(h);
		expect(h.stand.marks.has("sam")).toBe(true);
		await empty();
		expect(h.stand.marks.has("sam")).toBe(false);
		expect(h.events).toEqual([]);
	});

	it("asks its withdraw again where its answer is lost, keeping the mark a registration sets meanwhile (c1a)", async () => {
		const h = wired();
		const empty = await setUp(h);
		let t2: string | undefined;
		h.firstRemoval(async (land) => {
			await land();
			await h.register("sam");
			t2 = h.stand.marks.get("sam");
			throw new Unavailable("passkey-witness");
		});
		const ended = await ending(empty());
		expect(t2).toBeDefined();
		expect(h.stand.marks.get("sam")).toBe(t2);
		expect(ended).toBe("answered");
		expect(h.events).toEqual([]);
	});

	it("keeps the mark a registration sets before its first withdraw lands late (c1a)", async () => {
		const h = wired();
		const empty = await setUp(h);
		let late: (() => Promise<void>) | undefined;
		h.firstRemoval(async (land) => {
			late = land;
			throw new Unavailable("passkey-witness");
		});
		const ended = await ending(empty());
		await h.register("sam");
		const t2 = h.stand.marks.get("sam");
		await late?.();
		expect(t2).toBeDefined();
		expect(h.stand.marks.get("sam")).toBe(t2);
		expect(ended).toBe("answered");
	});

	it("leaves the mark of a registration made after another call settled, once it resumes (c1b)", async () => {
		const h = wired();
		const empty = await setUp(h);
		let t2: string | undefined;
		h.state.paused = async () => {
			await h.holders.cleared("sam");
			expect(h.stand.marks.has("sam")).toBe(false);
			await h.register("sam");
			t2 = h.stand.marks.get("sam");
		};
		const ended = await ending(empty());
		expect(t2).toBeDefined();
		expect(h.stand.marks.get("sam")).toBe(t2);
		expect(ended).toBe("answered");
		expect(h.events).toEqual([]);
	});

	it("leaves the mark of a registration made between its reads and its withdraw (c1b)", async () => {
		const h = wired();
		const empty = await setUp(h);
		let t2: string | undefined;
		h.firstRemoval(async (land) => {
			await h.holders.cleared("sam");
			await h.register("sam");
			t2 = h.stand.marks.get("sam");
			await land();
		});
		const ended = await ending(empty());
		expect(t2).toBeDefined();
		expect(h.stand.marks.get("sam")).toBe(t2);
		expect(ended).toBe("answered");
		expect(h.events).toEqual([]);
	});

	it("does nothing for a registration still writing when it resumes, which marks once admitted (c1b)", async () => {
		const h = wired();
		const empty = await setUp(h);
		let b: Awaited<ReturnType<Wired["pending"]>> | undefined;
		h.state.paused = async () => {
			await h.holders.cleared("sam");
			b = await h.pending("sam");
		};
		const enrolls: string[] = [];
		const enroll = h.stand.witness.enroll;
		h.stand.witness.enroll = async (subject, token) => {
			enrolls.push(token);
			return enroll(subject, token);
		};
		const ended = await ending(empty());
		expect(enrolls).toEqual([]);
		expect(h.stand.marks.has("sam")).toBe(false);
		await b?.admit();
		expect(h.stand.marks.has("sam")).toBe(true);
		expect(ended).toBe("answered");
		expect(h.events).toEqual([]);
	});

	it("marks again for a registration that relied on the mark it withdraws (c1′)", async () => {
		const h = wired();
		const empty = await setUp(h);
		const old = h.stand.marks.get("sam");
		h.firstRemoval(async (land) => {
			await h.register("sam");
			expect(h.stand.marks.get("sam")).toBe(old);
			await land();
		});
		const ended = await ending(empty());
		expect(h.stand.marks.has("sam")).toBe(true);
		expect(h.stand.marks.get("sam")).not.toBe(old);
		expect(await h.holders.held("sam")).toBe(true);
		expect(ended).toBe("answered");
		expect(h.events).toEqual([]);
	});

	it("leaves a registration pending when it withdraws unmarked, which marks once admitted (c1′)", async () => {
		const h = wired();
		const empty = await setUp(h);
		let b: Awaited<ReturnType<Wired["pending"]>> | undefined;
		h.firstRemoval(async (land) => {
			b = await h.pending("sam");
			await land();
		});
		const ended = await ending(empty());
		expect(h.stand.marks.has("sam")).toBe(false);
		await b?.admit();
		expect(h.stand.marks.has("sam")).toBe(true);
		expect(ended).toBe("answered");
		expect(h.events).toEqual([]);
	});

	it("is unsure where a registration made meanwhile loses its record, keeping its mark (Astra)", async () => {
		const h = wired();
		const empty = await setUp(h);
		let t2: string | undefined;
		h.state.paused = async () => {
			await h.holders.cleared("sam");
			const id = await h.register("sam");
			t2 = h.stand.marks.get("sam");
			await h.stores.lose.record(id);
		};
		const ended = await ending(empty());
		expect(t2).toBeDefined();
		expect(h.stand.marks.get("sam")).toBe(t2);
		expect(h.events).toEqual(inconsistent(at));
		expect(ended).toBe("unavailable");
	});

	it("is unsure where the holder is lost after its write, keeping the mark", async () => {
		const h = wired();
		const empty = await setUp(h);
		const old = h.stand.marks.get("sam");
		h.state.paused = () => h.stores.lose.holder("sam");
		const ended = await ending(empty());
		expect(h.stand.marks.get("sam")).toBe(old);
		expect(h.events).toEqual(inconsistent(at));
		expect(ended).toBe("unavailable");
	});

	it("is unsure where the holder is made anew after its write, keeping the mark", async () => {
		const h = wired();
		const empty = await setUp(h);
		const old = h.stand.marks.get("sam");
		h.state.paused = async () => {
			await h.stores.lose.holder("sam");
			await h.records.handleFor("sam", fresh());
		};
		const ended = await ending(empty());
		expect(h.stand.marks.get("sam")).toBe(old);
		expect(h.events).toEqual(inconsistent(at));
		expect(ended).toBe("unavailable");
	});

	it("is unsure where the holder goes back to its copy from before the write, keeping the mark", async () => {
		const h = wired();
		const empty = await setUp(h);
		const old = h.stand.marks.get("sam");
		const copy = h.stores.holderCopy("sam") as object;
		h.state.paused = () => h.stores.backTo("sam", copy);
		const ended = await ending(empty());
		expect(h.stand.marks.get("sam")).toBe(old);
		expect(h.events).toEqual(inconsistent(at));
		expect(ended).toBe("unavailable");
	});

	it("is unsure where the holder goes back to a copy of the one lost before, its fence ahead (Astra, second)", async () => {
		const h = wired();
		const older = { v: 1, handle: fresh(), credentials: [], fence: 5 };
		await h.stores.backTo("sam", older);
		await h.stores.lose.holder("sam");
		// The repair: a reset makes the holder anew.
		await h.holders.cleared("sam");
		const empty = await setUp(h);
		let t2: string | undefined;
		h.state.paused = async () => {
			await h.holders.cleared("sam");
			await h.register("sam");
			t2 = h.stand.marks.get("sam");
			await h.stores.backTo("sam", older);
		};
		const ended = await ending(empty());
		expect(t2).toBeDefined();
		expect(h.stand.marks.get("sam")).toBe(t2);
		expect(h.events).toEqual(inconsistent(at));
		expect(ended).toBe("unavailable");
	});

	it("is unavailable once its withdraw stays unavailable past its retries, reading nothing again", async () => {
		const h = wired();
		const empty = await setUp(h);
		const old = h.stand.marks.get("sam");
		Object.assign(h.reads, { markedWith: 0, afterRemoval: 0 });
		h.stand.failing.withdraw = 4;
		const ended = await ending(empty());
		expect(h.stand.marks.get("sam")).toBe(old);
		expect(h.reads).toEqual({ markedWith: 1, afterRemoval: 1 });
		expect(ended).toBe("unavailable");
		expect(h.events).toEqual([]);
	});
});

it("mends a subject whose store lost its passkeys and holder, the mark alone left: a reset makes the holder anew and withdraws it", async () => {
	const h = wired();
	const id = await h.register("dee");
	const lost = (await h.records.holder("dee"))?.handle;
	await h.stores.lose.holder("dee");
	await h.stores.lose.record(id);
	expect(await h.holders.cleared("dee")).toEqual({ removed: 0 });
	expect(h.stand.marks.has("dee")).toBe(false);
	const holder = await h.records.holder("dee");
	expect(holder).toMatchObject({ credentials: [], fence: 1 });
	expect(holder?.handle).not.toBe(lost);
	expect(await h.holders.held("dee")).toBe(false);
	expect(h.events).toEqual([]);
});
