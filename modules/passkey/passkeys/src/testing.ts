import { randomBytes } from "node:crypto";
import { defineModule, isUnavailable, Unavailable } from "@mod/kernel";
import { describe, expect, it } from "vitest";
import type { z } from "zod";
import { keptPasskeys } from "./records.ts";
import type { section } from "./section.ts";
import type {
	ChallengeStore,
	PasskeyRecords,
	PasskeyStore,
	StoredChallenge,
	StoredPasskey,
} from "./store.ts";
import { type PasskeyWitness, passkeyWitnesses } from "./witness.ts";

export type PasskeysSettings = z.input<typeof section>;

/** The passkeys part of a test's configuration: the section's defaults, but for what is given. */
export function passkeysConfig(settings: Partial<PasskeysSettings> = {}) {
	return { passkeys: { ...settings } };
}

/** A place that keeps passkeys', as one implementation of its store interface offers it. */
export interface PasskeyPlace {
	readonly passkeys: PasskeyStore;
	/** Moves the place's clock on. */
	advance(ms: number): void;
	/** Before the next update of a subject's `key` writes, another writer changes its record as given. */
	raceNextUpdate(key: string, change: (record: StoredPasskey) => StoredPasskey): void;
	/** Where answers can be lost: the next write takes effect, but its answer is lost. */
	readonly loseNextAnswer?: () => void;
	/** Where the place replicates: a replica takes over, keeping only what was confirmed. */
	readonly failover?: () => Promise<void>;
	/** Where the place can restart: it does, keeping only what it holds durably. */
	readonly restart?: () => Promise<void>;
	/** Where memory can run short: it does, keeping only what is kept from eviction. */
	readonly pressMemory?: () => Promise<void>;
	/** Where reads can meet unconfirmed writes: runs `during` as the next save takes effect, unconfirmed. */
	readonly duringNextSave?: (during: () => Promise<void>) => void;
	/** Where another writer can come between: before the next records changed as one are written, it changes the record at `key` of `space` as given. */
	readonly raceNextTogether?: (
		space: "credentials" | "subjects",
		key: string,
		change: (record: StoredPasskey) => StoredPasskey,
	) => void;
}

const handleOf = () => randomBytes(32).toString("base64url");
const writeToken = () => randomBytes(16).toString("base64url");

/** What passkeys needs from any implementation: records kept whole and apart, without end, written by passkeys in one shape. */
export function passkeyStoreContract(name: string, open: () => Promise<PasskeyPlace>): void {
	let n = 0;
	const fresh = () => `k-${++n}-${randomBytes(6).toString("hex")}`;
	const held = (value: object) => value as unknown as StoredPasskey;
	const counted = (record: StoredPasskey) => (record as unknown as { n: number }).n;
	const plus = (by: number) => (record: StoredPasskey) => ({
		value: held({ n: counted(record) + by }),
	});

	describe(`passkeys' passkey store interface: ${name}`, () => {
		it("keeps a record whole and once per key in each space, the two apart", async () => {
			const { passkeys } = await open();
			const key = fresh();
			const odd = held({ state: "unheard-of", nested: { list: [1, "two"] } });
			expect(await passkeys.credentials.save(key, odd, "endless")).toBe("created");
			expect(await passkeys.credentials.save(key, held({ n: 1 }), "endless")).toBe("exists");
			expect(await passkeys.subjects.read(key)).toBeUndefined();
			expect(await passkeys.subjects.save(key, held({ n: 1 }), "endless")).toBe("created");
			expect(await passkeys.credentials.read(key)).toEqual(odd);
			expect(await passkeys.subjects.update(key, plus(1))).toEqual({
				before: held({ n: 1 }),
				after: held({ n: 2 }),
			});
			expect(await passkeys.credentials.update(fresh(), plus(1))).toBeUndefined();
		});

		it("changes records of both spaces as one, giving the change what it watched, each space apart", async () => {
			const { passkeys } = await open();
			const together = passkeys.updateTogether.bind(passkeys);
			// One key in both spaces, and the owner's in both: each space keeps its own.
			const [key, owner] = [fresh(), fresh()];
			await passkeys.subjects.save(owner, held({ n: 7 }), "endless");
			await passkeys.credentials.save(owner, held({ n: 9 }), "endless");
			const seen: unknown[] = [];
			const first = await together(
				{ credentials: [key], subjects: [key] },
				{
					watch: () => ({ subjects: [owner] }),
					change: (read) => {
						seen.push(read);
						return {
							credentials: [{ value: held({ n: 1 }) }],
							subjects: [{ value: held({ n: 2 }) }],
						};
					},
				},
			);
			expect(seen).toEqual([{ credentials: [undefined], subjects: [undefined, held({ n: 7 })] }]);
			expect(first).toEqual({
				credentials: [{ before: undefined, after: held({ n: 1 }) }],
				subjects: [
					{ before: undefined, after: held({ n: 2 }) },
					{ before: held({ n: 7 }), after: held({ n: 7 }) },
				],
			});
			expect([
				await passkeys.credentials.read(key),
				await passkeys.subjects.read(key),
				await passkeys.credentials.read(owner),
			]).toEqual([held({ n: 1 }), held({ n: 2 }), held({ n: 9 })]);
			// A record it leaves out is kept.
			const kept = await together(
				{ credentials: [key], subjects: [key] },
				{ watch: () => ({}), change: () => ({ subjects: [plus(1)(held({ n: 2 }))] }) },
			);
			expect(kept).toEqual({
				credentials: [{ before: held({ n: 1 }), after: held({ n: 1 }) }],
				subjects: [{ before: held({ n: 2 }), after: held({ n: 3 }) }],
			});
		});

		it("writes the records it watched as well, as a subject's list and the credentials it names", async () => {
			const { passkeys } = await open();
			const together = passkeys.updateTogether.bind(passkeys);
			const [list, a, b] = [fresh(), fresh(), fresh()];
			await passkeys.subjects.save(list, held({ ids: [a, b] }), "endless");
			await passkeys.credentials.save(a, held({ n: 1 }), "endless");
			const idsOf = (record: StoredPasskey | undefined) =>
				(record as unknown as { ids?: string[] } | undefined)?.ids ?? [];
			const cleared = await together(
				{ credentials: [], subjects: [list] },
				{
					watch: ({ subjects: [held] }) => ({ credentials: idsOf(held) }),
					change: ({ credentials }) => ({
						subjects: [{ value: held({ ids: [] }) }],
						credentials: credentials.map((record) => record && { value: held({ gone: true }) }),
					}),
				},
			);
			expect(cleared).toEqual({
				credentials: [
					{ before: held({ n: 1 }), after: held({ gone: true }) },
					{ before: undefined, after: undefined },
				],
				subjects: [{ before: held({ ids: [a, b] }), after: held({ ids: [] }) }],
			});
			expect([await passkeys.credentials.read(a), await passkeys.credentials.read(b)]).toEqual([
				held({ gone: true }),
				undefined,
			]);
		});

		it("changes records as one again where another writer changes what it watched first", async (ctx) => {
			const { passkeys, raceNextTogether: race } = await open();
			const together = passkeys.updateTogether.bind(passkeys);
			if (!race) {
				ctx.skip();
				return;
			}
			const [key, owner, other] = [fresh(), fresh(), fresh()];
			await passkeys.credentials.save(key, held({ owner }), "endless");
			await passkeys.subjects.save(owner, held({ n: 1 }), "endless");
			await passkeys.subjects.save(other, held({ n: 2 }), "endless");
			const ownerOf = (record: StoredPasskey | undefined) =>
				(record as unknown as { owner?: string } | undefined)?.owner;
			const watched: unknown[] = [];
			const run = () =>
				together(
					{ credentials: [key], subjects: [] },
					{
						watch: ({ credentials: [credential] }) => {
							const o = ownerOf(credential);
							return { subjects: o ? [o] : [] };
						},
						change: ({ subjects: [list] }) => {
							watched.push(list);
							return {};
						},
					},
				);
			// The watched list changes first: read again.
			race("subjects", owner, () => held({ n: 10 }));
			await run();
			expect(watched).toEqual([held({ n: 1 }), held({ n: 10 })]);
			// The credential's owner changes first: the new owner is watched, and read.
			watched.length = 0;
			race("credentials", key, () => held({ owner: other }));
			await run();
			expect(watched).toEqual([held({ n: 10 }), held({ n: 2 })]);
		});

		it("changes a record only from what it holds, again after a racing writer", async () => {
			const place = await open();
			const key = fresh();
			await place.passkeys.subjects.save(key, held({ n: 1 }), "endless");
			place.raceNextUpdate(key, (record) => held({ n: counted(record) * 10 }));
			expect((await place.passkeys.subjects.update(key, plus(1)))?.after).toEqual(held({ n: 11 }));
		});

		it("keeps records without end, through a restart and through memory pressure", async () => {
			const place = await open();
			const key = fresh();
			await place.passkeys.credentials.save(key, held({ n: 1 }), "endless");
			place.advance(10 * 365 * 86_400_000);
			await place.restart?.();
			await place.pressMemory?.();
			expect(await place.passkeys.credentials.read(key)).toEqual(held({ n: 1 }));
		});

		it("settles writes whose answers were lost, and keeps them through a failover", async (context) => {
			const place = await open();
			const { loseNextAnswer: lose, failover } = place;
			if (!lose || !failover) return context.skip();
			const key = fresh();
			lose();
			expect(await place.passkeys.subjects.save(key, held({ n: 1 }), "endless")).toBe("created");
			lose();
			expect((await place.passkeys.subjects.update(key, plus(1)))?.after).toEqual(held({ n: 2 }));
			await failover();
			expect(await place.passkeys.subjects.read(key)).toEqual(held({ n: 2 }));
		});

		// The writer gives up once the clock passes its patience, so only the read could have kept it.
		it("reads a record another request wrote only as a failover keeps it", async (context) => {
			const place = await open();
			const { duringNextSave, failover } = place;
			if (!duringNextSave || !failover) return context.skip();
			const key = fresh();
			let seen: StoredPasskey | undefined;
			duringNextSave(async () => {
				seen = await place.passkeys.credentials.read(key);
				await failover();
				place.advance(60_000);
			});
			await place.passkeys.credentials.save(key, held({ n: 1 }), "endless").catch(() => undefined);
			expect(await place.passkeys.credentials.read(key)).toEqual(seen);
		});

		it("is never given a handle or a credential id passkeys would not write", async () => {
			const { passkeys } = await open();
			const records = keptPasskeys(passkeys, writeToken);
			const subject = fresh();
			const padded = `${handleOf()}=`;
			await expect(records.handleFor(subject, padded)).rejects.toThrow(
				"a handle must be canonical",
			);
			expect(await records.holder(subject)).toBeUndefined();
			const handle = await records.handleFor(subject, handleOf());
			const credential = {
				id: "AAAA",
				publicKey: "pQ",
				signCount: 0,
				userHandle: handle,
				backupEligible: false,
				backedUp: false,
			};
			for (const [name, twisted] of Object.entries({
				"id not canonical": { ...credential, id: "AAB" },
				"id padded": { ...credential, id: "AAAA==" },
				"handle padded": { ...credential, userHandle: `${handle}=` },
			})) {
				expect(await records.register(subject, twisted, 10), name).toBe("malformed");
			}
			expect(await records.passkey("AAB")).toBeUndefined();
			expect((await records.holder(subject))?.credentials).toEqual([]);
			expect(await records.register(subject, credential, 10)).toBe("registered");
			expect((await records.passkey("AAAA"))?.subject).toBe(subject);
		});

		it("answers unavailable for a record not in the shape passkeys writes", async () => {
			const { passkeys } = await open();
			const keys: string[] = [];
			const spied = (records: PasskeyRecords): PasskeyRecords => ({
				...records,
				save: (key, record, lifetimeMs) => {
					keys.push(key);
					return records.save(key, record, lifetimeMs);
				},
			});
			const [subject, id] = [fresh(), randomBytes(16).toString("base64url")];
			const watched: PasskeyStore = {
				credentials: spied(passkeys.credentials),
				subjects: spied(passkeys.subjects),
				// A registration writes its record together with its listing: its key is the first named.
				updateTogether: (named, p) => {
					keys.push(...named.credentials);
					return passkeys.updateTogether(named, p);
				},
			};
			const records = keptPasskeys(watched, writeToken);
			const userHandle = await records.handleFor(subject, handleOf());
			const kept = {
				id,
				publicKey: "pQ",
				signCount: 0,
				userHandle,
				backupEligible: false,
				backedUp: false,
			};
			expect(await records.register(subject, kept, 10)).toBe("registered");
			const [holderKey = "", credentialKey = ""] = keys;
			const twist = (record: StoredPasskey) => ({ value: held({ ...record, v: 2 }) });
			await passkeys.subjects.update(holderKey, twist);
			await passkeys.credentials.update(credentialKey, twist);
			for (const read of [() => records.holder(subject), () => records.passkey(id)]) {
				await expect(read()).rejects.toSatisfy(isUnavailable);
			}
		});
	});
}

/** A place that keeps passkeys' challenges, as one implementation of its store interface offers it. */
export interface ChallengePlace {
	readonly challenges: ChallengeStore;
	/** Moves the place's clock on, so lifetimes run out. */
	advance(ms: number): void;
	/** Where answers can be lost: the next write takes effect, but its answer is lost. */
	readonly loseNextAnswer?: () => void;
	/** Where the place replicates: a replica takes over, keeping only what was confirmed. */
	readonly failover?: () => Promise<void>;
	/** Where the place can restart: it does, keeping only what it holds durably. */
	readonly restart?: () => Promise<void>;
	/** Where what the place was given can be searched: whether any of it carried `text`. */
	readonly holds?: (text: string) => boolean;
}

/** What passkeys needs from any implementation: a challenge kept once for its lifetime, taken once, never in clear. */
export function challengeStoreContract(name: string, open: () => Promise<ChallengePlace>): void {
	const fresh = () => randomBytes(32).toString("base64url");
	const held = (value: object) => value as unknown as StoredChallenge;
	const mark = held({ taken: true });

	describe(`passkeys' challenge store interface: ${name}`, () => {
		it("keeps a challenge once, and puts the mark in its place for the rest of its lifetime", async () => {
			const place = await open();
			const challenge = fresh();
			const record = held({ kind: "assertion", nested: [1, "two"] });
			expect(await place.challenges.open(challenge, record, 1000)).toBe("created");
			expect(await place.challenges.open(challenge, held({ n: 1 }), 1000)).toBe("exists");
			place.advance(500);
			expect(await place.challenges.take(challenge, mark)).toEqual({ before: record, after: mark });
			expect(await place.challenges.take(challenge, mark)).toEqual({ before: mark, after: mark });
			place.advance(500);
			expect(await place.challenges.take(challenge, mark)).toBeUndefined();
			expect(await place.challenges.take(fresh(), mark)).toBeUndefined();
		});

		it("never gives a challenge to what the place holds, in clear", async (context) => {
			const place = await open();
			const { holds } = place;
			if (!holds) return context.skip();
			const [challenge, kept] = [fresh(), fresh()];
			await place.challenges.open(challenge, held({ kept }), 60_000);
			await place.challenges.take(challenge, mark);
			expect([holds(kept), holds(challenge)]).toEqual([true, false]);
		});

		it("keeps a taken mark through a restart, a lost answer and a failover", async (context) => {
			const place = await open();
			const { restart, loseNextAnswer: lose, failover } = place;
			if (!restart || !lose || !failover) return context.skip();
			const challenge = fresh();
			await place.challenges.open(challenge, held({ n: 1 }), 60_000);
			lose();
			expect((await place.challenges.take(challenge, mark))?.before).toEqual(held({ n: 1 }));
			await restart();
			await failover();
			expect((await place.challenges.take(challenge, mark))?.before).toEqual(mark);
		});
	});
}

/**
 * A passkey witness in memory, keeping its promises: each call fails as unavailable while its count
 * of failures lasts, and `lost` writes take effect with their answer lost. It offers `clear` unless
 * made without it. `beforeEnroll`,
 * `afterEnroll`, `beforeRead` and `beforeWithdraw` run once around the next such call, as a request
 * racing it would.
 */
export function passkeyWitnessStandIn(
	name = "passkey-witness",
	{ clear = true }: { readonly clear?: boolean } = {},
) {
	const marks = new Map<string, string>();
	const failing = { read: 0, markedWith: 0, enroll: 0, withdraw: 0, clear: 0 };
	const lost = { enroll: 0, withdraw: 0, clear: 0 };
	const next: {
		beforeEnroll?: (() => void) | undefined;
		afterEnroll?: (() => void) | undefined;
		beforeRead?: (() => void) | undefined;
		beforeWithdraw?: (() => void) | undefined;
	} = {};
	const once = (hook: keyof typeof next) => {
		const run = next[hook];
		next[hook] = undefined;
		run?.();
	};
	const fails = (call: keyof typeof failing) => {
		if (failing[call] === 0) return;
		failing[call] -= 1;
		throw new Unavailable("passkey-witness");
	};
	const loses = (call: keyof typeof lost) => {
		if (lost[call] === 0) return;
		lost[call] -= 1;
		throw new Unavailable("passkey-witness");
	};
	const witness: PasskeyWitness = {
		read: async (subject) => {
			fails("read");
			once("beforeRead");
			return marks.has(subject);
		},
		enroll: async (subject, token) => {
			fails("enroll");
			once("beforeEnroll");
			if (!marks.has(subject)) marks.set(subject, token);
			const owned = marks.get(subject) === token;
			once("afterEnroll");
			loses("enroll");
			return owned;
		},
		withdraw: async (subject, token) => {
			fails("withdraw");
			once("beforeWithdraw");
			if (marks.get(subject) === token) marks.delete(subject);
			loses("withdraw");
		},
		markedWith: async (subject) => {
			fails("markedWith");
			return marks.get(subject);
		},
		...(clear && {
			clear: async (subject: string) => {
				fails("clear");
				marks.delete(subject);
				loses("clear");
			},
		}),
	};
	const module = defineModule({ name }, (m) => [m.contribute(passkeyWitnesses).by(() => witness)]);
	return { module, witness, marks, failing, lost, next };
}

/** Where an implementation breaks the passkey witness's promises, by what was asked; none when it keeps them. */
export async function passkeyWitnessProblems(witness: PasskeyWitness): Promise<string[]> {
	const problems: string[] = [];
	const n = Math.random().toString(36).slice(2);
	const check = (holds: boolean, what: string) => {
		if (!holds) problems.push(what);
	};
	// Built where no type is checked, a witness may lack it.
	if (typeof witness.markedWith !== "function")
		return ["the witness does not tell its mark's token"];
	/** Whether the witness tells `token` as its mark's. */
	const tokenIs = async (subject: string, token: string | undefined, what: string) => {
		check((await witness.markedWith(subject)) === token, what);
	};
	const one = `p-${n}-1`;
	check(!(await witness.read(one)), "a subject never marked reads as marked");
	await tokenIs(one, undefined, "markedWith answers a token for a subject never marked");
	check(await witness.enroll(one, "t1"), "the first enroll does not own the mark");
	check(await witness.read(one), "a read after an answered enroll misses it");
	await tokenIs(one, "t1", "markedWith misses the token its enroll owned");
	check(!(await witness.enroll(one, "t2")), "a second token owns the mark");
	check(await witness.enroll(one, "t1"), "the owner's token, sent again, does not own the mark");
	await witness.withdraw(one, "t2");
	check(await witness.read(one), "a withdraw by another token removed the mark");
	await tokenIs(one, "t1", "markedWith answers another token than the mark's");
	await witness.withdraw(one, "t1");
	check(!(await witness.read(one)), "a withdraw by the owner's token left the mark");
	await tokenIs(one, undefined, "markedWith answers the token of a mark withdrawn");
	await witness.withdraw(one, "t1");
	check(!(await witness.read(one)), "a withdraw where no mark is set made one");
	check(await witness.enroll(one, "t3"), "a token after a withdraw does not own the mark");
	if (witness.clear) {
		await witness.clear(one);
		check(!(await witness.read(one)), "a read after an answered clear still sees the mark");
		await tokenIs(one, undefined, "markedWith answers the token of a mark cleared");
	}
	const two = `p-${n}-2`;
	const raced = await Promise.all([witness.enroll(two, "a"), witness.enroll(two, "b")]);
	check(raced.filter(Boolean).length === 1, "two enrolls at once do not leave exactly one owner");
	// Another's mark: the token its owner set, whichever won.
	await tokenIs(two, raced[0] ? "a" : "b", "markedWith answers another token than the mark's");
	return problems;
}

/** What passkeys needs from any witness: set-if-absent by token, withdraw by token, the mark's token, clear where it offers it, and reads never behind an answered write. */
export function passkeyWitnessContract(name: string, open: () => Promise<PasskeyWitness>) {
	describe(`passkey witness contract: ${name}`, () => {
		it("keeps the mark by its first token, withdraws it only by that token, tells its token, clears it where it can, and reads every answered write", async () => {
			expect(await passkeyWitnessProblems(await open())).toEqual([]);
		});
	});
}
