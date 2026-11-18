import { randomBytes } from "node:crypto";
import { isUnavailable } from "@mod/kernel";
import { describe, expect, it } from "vitest";
import type { z } from "zod";
import { keptPasskeys } from "./records.ts";
import type { section } from "./section.ts";
import {
	type ChallengeStore,
	challengeStoreNeeds,
	type PasskeyOp,
	type PasskeyRecords,
	type PasskeyStore,
	type RegistrationChallengeStore,
	type StoredChallenge,
	type StoredPasskey,
} from "./store.ts";

type AsOne = Parameters<PasskeyStore["updateAsOne"]>[0];

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
			expect(await passkeys.credentials.save(key, odd, "endless", "alice")).toBe("created");
			expect(await passkeys.credentials.save(key, held({ n: 1 }), "endless", "alice")).toBe(
				"exists",
			);
			expect(await passkeys.subjects.read(key)).toBeUndefined();
			expect(await passkeys.subjects.save(key, held({ n: 1 }), "endless", "alice")).toBe("created");
			expect(await passkeys.credentials.read(key)).toEqual(odd);
			expect(await passkeys.subjects.update(key, plus(1))).toEqual({
				before: held({ n: 1 }),
				after: held({ n: 2 }),
			});
			expect(await passkeys.credentials.update(fresh(), plus(1))).toBeUndefined();
		});

		it("writes the records it watched as well, as a subject's list and the credentials it names", async () => {
			const { passkeys } = await open();
			const [list, a, b] = [fresh(), fresh(), fresh()];
			await passkeys.subjects.save(list, held({ ids: [a, b] }), "endless", "alice");
			await passkeys.credentials.save(a, held({ n: 1 }), "endless", "alice");
			const idsOf = (record: StoredPasskey | undefined) =>
				(record as unknown as { ids?: string[] } | undefined)?.ids ?? [];
			const change = (value: StoredPasskey): PasskeyOp => ({ kind: "change", value });
			const cleared = await passkeys.updateAsOne({
				targets: [{ place: "subjects", key: list }],
				watch: ([holder]) =>
					idsOf(holder?.value).map((key) => ({ place: "credentials" as const, key })),
				decide: (_read, watched) => ({
					targets: [change(held({ ids: [] }))],
					watched: watched.map((record) => record && change(held({ gone: true }))),
				}),
			});
			expect(cleared.kind).toBe("written");
			if (cleared.kind !== "written") return;
			expect(cleared.targets.map((c) => [c.before?.value, c.after?.value])).toEqual([
				[held({ ids: [a, b] }), held({ ids: [] })],
			]);
			expect(cleared.watched.map((c) => [c.before?.value, c.after?.value])).toEqual([
				[held({ n: 1 }), held({ gone: true })],
				[undefined, undefined],
			]);
			expect([await passkeys.credentials.read(a), await passkeys.credentials.read(b)]).toEqual([
				held({ gone: true }),
				undefined,
			]);
		});

		it("changes records as one again where another writer changes what it watched first, keeping a record given no op", async (ctx) => {
			const { passkeys, raceNextTogether: race } = await open();
			if (!race) return ctx.skip();
			const [key, owner, other] = [fresh(), fresh(), fresh()];
			await passkeys.credentials.save(key, held({ owner }), "endless", "alice");
			await passkeys.subjects.save(owner, held({ n: 1 }), "endless", "alice");
			await passkeys.subjects.save(other, held({ n: 2 }), "endless", "alice");
			const ownerOf = (record: StoredPasskey | undefined) =>
				(record as unknown as { owner?: string } | undefined)?.owner;
			const watched: unknown[] = [];
			const run = () =>
				passkeys.updateAsOne({
					targets: [{ place: "credentials", key }],
					watch: ([credential]) => {
						const o = ownerOf(credential?.value);
						return o ? [{ place: "subjects", key: o }] : [];
					},
					decide: (_read, [list]) => {
						watched.push(list?.value);
						return {};
					},
				});
			// The watched list changes first: read again.
			race("subjects", owner, () => held({ n: 10 }));
			expect((await run()).kind).toBe("written");
			expect(watched).toEqual([held({ n: 1 }), held({ n: 10 })]);
			// The credential's owner changes first: the new owner is watched, and read.
			watched.length = 0;
			race("credentials", key, () => held({ owner: other }));
			await run();
			expect(watched).toEqual([held({ n: 10 }), held({ n: 2 })]);
			// Given no op, each record is kept as it was.
			expect(await passkeys.credentials.read(key)).toEqual(held({ owner: other }));
			expect(await passkeys.subjects.read(owner)).toEqual(held({ n: 10 }));
		});

		it("changes records of both spaces as one by the ops decided, writing nothing where one is refused", async (_context) => {
			const { passkeys } = await open();
			const asOne = (p: AsOne) => passkeys.updateAsOne(p);
			const [list, record, other] = [fresh(), fresh(), fresh()];
			const [inList, inRecords] = [
				{ place: "subjects" as const, key: list },
				{ place: "credentials" as const, key: record },
			];
			const create = (n: number): PasskeyOp => ({
				kind: "create",
				value: held({ n }),
				lifetimeMs: "endless",
				subject: "alice",
			});
			const written = await asOne({
				targets: [inRecords, inList],
				decide: () => ({ targets: [create(1), create(2)] }),
			});
			expect(written).toMatchObject({
				kind: "written",
				targets: [{ after: { value: { n: 1 } } }, {}],
			});
			const refused = await asOne({
				targets: [{ place: "credentials", key: other }, inList],
				decide: () => ({ targets: [create(3), create(4)] }),
			});
			expect(refused).toEqual({ kind: "refused", at: { in: "targets", nth: 1 }, why: "exists" });
			expect(await passkeys.credentials.read(other)).toBeUndefined();
			const moved = await asOne({
				targets: [inRecords],
				watch: () => [inList],
				decide: () => ({ targets: [{ kind: "move", value: held({ n: 5 }), to: "alice" }] }),
			});
			expect(moved).toMatchObject({ kind: "written", watched: [{ after: { value: { n: 2 } } }] });
			expect(await passkeys.credentials.read(record)).toEqual(held({ n: 5 }));
			// The two spaces stay apart: one key, a record in each.
			expect(await passkeys.subjects.read(record)).toBeUndefined();
		});

		it("refuses, where it erases, every record saved for a subject it erased, in each space and only for that subject", async (context) => {
			const { passkeys } = await open();
			for (const space of [passkeys.credentials, passkeys.subjects]) {
				const { erase } = space;
				if (!erase) return context.skip();
				await space.save(fresh(), held({ n: 1 }), "endless", "erin");
				const report = await erase.call(space, "erin", new AbortController().signal);
				// A Store that erases nothing now (its records not indexed yet) says so, and fences nothing.
				if (report.kind === "stopped") return context.skip();
				expect(report.kind).toBe("erased");
				expect(await space.save(fresh(), held({ n: 2 }), "endless", "erin")).toBe("erased");
				expect(await space.save(fresh(), held({ n: 3 }), "endless", "finn")).toBe("created");
			}
		});

		it("changes a record only from what it holds, again after a racing writer", async () => {
			const place = await open();
			const key = fresh();
			await place.passkeys.subjects.save(key, held({ n: 1 }), "endless", "alice");
			place.raceNextUpdate(key, (record) => held({ n: counted(record) * 10 }));
			expect((await place.passkeys.subjects.update(key, plus(1)))?.after).toEqual(held({ n: 11 }));
		});

		it("keeps records without end, through a restart and through memory pressure", async () => {
			const place = await open();
			const key = fresh();
			await place.passkeys.credentials.save(key, held({ n: 1 }), "endless", "alice");
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
			expect(await place.passkeys.subjects.save(key, held({ n: 1 }), "endless", "alice")).toBe(
				"created",
			);
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
			await place.passkeys.credentials
				.save(key, held({ n: 1 }), "endless", "alice")
				.catch(() => undefined);
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
				save: (...given) => {
					keys.push(given[0]);
					return records.save(...given);
				},
			});
			const [subject, id] = [fresh(), randomBytes(16).toString("base64url")];
			// A registration writes its record together with its listing: its key is the first named.
			const watched: PasskeyStore = {
				credentials: spied(passkeys.credentials),
				subjects: spied(passkeys.subjects),
				updateAsOne: (p: AsOne) => {
					keys.push(...p.targets.filter((t) => t.place === "credentials").map((t) => t.key));
					return passkeys.updateAsOne(p);
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

/** A place that keeps passkeys' registration challenges, as one implementation of its store interface offers it. */
export interface RegistrationChallengePlace extends Omit<ChallengePlace, "challenges"> {
	readonly registrations: RegistrationChallengeStore;
}

/**
 * What passkeys needs from any implementation of the registration challenge store: a challenge
 * kept once for its subject and its lifetime, up to the longest passkeys keeps one, marked once,
 * never in clear; where it erases, none opened for an erased subject.
 */
export function registrationChallengeStoreContract(
	name: string,
	open: () => Promise<RegistrationChallengePlace>,
): void {
	const fresh = () => randomBytes(32).toString("base64url");
	const held = (value: object) => value as unknown as StoredChallenge;
	const mark = held({ taken: true });
	const marked = () => ({ value: mark });

	describe(`passkeys' registration challenge store interface: ${name}`, () => {
		it("keeps a challenge once for its subject, and puts the mark in its place for the rest of its lifetime", async () => {
			const place = await open();
			const { registrations } = place;
			const challenge = fresh();
			const record = held({ kind: "registration", nested: [1, "two"] });
			expect(await registrations.open(challenge, record, 1000, "alice")).toBe("created");
			expect(await registrations.open(challenge, held({ n: 1 }), 1000, "alice")).toBe("exists");
			place.advance(500);
			expect(await registrations.update(challenge, marked)).toEqual({
				before: record,
				after: mark,
			});
			expect(await registrations.update(challenge, marked)).toEqual({ before: mark, after: mark });
			place.advance(500);
			expect(await registrations.update(challenge, marked)).toBeUndefined();
			expect(await registrations.update(fresh(), marked)).toBeUndefined();
		});

		it("keeps a challenge opened for the longest passkeys keeps one, until that end", async () => {
			const place = await open();
			const { registrations } = place;
			const longest = challengeStoreNeeds.registrationsEndWithinMs;
			const [challenge, record] = [fresh(), held({ kind: "registration" })];
			expect(await registrations.open(challenge, record, longest, "alice")).toBe("created");
			place.advance(longest - 1000);
			expect((await registrations.update(challenge, marked))?.before).toEqual(record);
			place.advance(1000);
			expect(await registrations.update(challenge, marked)).toBeUndefined();
		});

		it("never gives a challenge to what the place holds, in clear", async (context) => {
			const place = await open();
			const { holds } = place;
			if (!holds) return context.skip();
			const [challenge, kept] = [fresh(), fresh()];
			await place.registrations.open(challenge, held({ kept }), 60_000, "alice");
			await place.registrations.update(challenge, marked);
			expect([holds(kept), holds(challenge)]).toEqual([true, false]);
		});

		it("keeps a mark through a restart, a lost answer and a failover", async (context) => {
			const place = await open();
			const { restart, loseNextAnswer: lose, failover } = place;
			if (!restart || !lose || !failover) return context.skip();
			const challenge = fresh();
			await place.registrations.open(challenge, held({ n: 1 }), 60_000, "alice");
			lose();
			expect((await place.registrations.update(challenge, marked))?.before).toEqual(held({ n: 1 }));
			await restart();
			await failover();
			expect((await place.registrations.update(challenge, marked))?.before).toEqual(mark);
		});

		it("opens none for a subject it erased, where it erases, and only for that subject", async (context) => {
			const { registrations } = await open();
			const { erase } = registrations;
			if (!erase) return context.skip();
			const [before, theirs] = [fresh(), fresh()];
			await registrations.open(before, held({ n: 1 }), 60_000, "erin");
			await registrations.open(theirs, held({ n: 2 }), 60_000, "finn");
			const report = await erase.call(registrations, "erin", new AbortController().signal);
			// A Store that erases nothing now (its records not indexed yet) says so, and fences nothing.
			if (report.kind === "stopped") return context.skip();
			expect(await registrations.open(fresh(), held({ n: 3 }), 60_000, "erin")).toBe("erased");
			// Fenced at opening only: one opened before is marked until its end.
			expect((await registrations.update(before, marked))?.before).toEqual(held({ n: 1 }));
			expect((await registrations.update(theirs, marked))?.before).toEqual(held({ n: 2 }));
			expect(await registrations.open(fresh(), held({ n: 4 }), 60_000, "finn")).toBe("created");
		});
	});
}
