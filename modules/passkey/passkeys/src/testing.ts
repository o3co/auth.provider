import { randomBytes } from "node:crypto";
import { isUnavailable } from "@mod/kernel";
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
}

const handleOf = () => randomBytes(32).toString("base64url");

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
			const records = keptPasskeys(passkeys);
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
			const watched = {
				credentials: spied(passkeys.credentials),
				subjects: spied(passkeys.subjects),
			};
			const records = keptPasskeys(watched);
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
