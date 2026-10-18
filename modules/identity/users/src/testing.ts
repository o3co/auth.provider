import { randomBytes, scryptSync } from "node:crypto";
import { defineModule, isUnavailable } from "@mod/kernel";
import { describe, expect, it } from "vitest";
import type { Contact, Ledger, Users } from "./contract.ts";
import {
	contactStore,
	linkStore,
	type RecordStore,
	type StoredContacts,
	type StoredLink,
} from "./store.ts";

const toUnpaddedBase64 = (bytes: Buffer) => bytes.toString("base64").replace(/=+$/, "");

/** A scrypt hash, by default with the cheapest work allowed. */
export function testPasswordHash(password: string, ln = 10): string {
	const salt = randomBytes(16);
	const key = scryptSync(password, salt, 32, { N: 2 ** ln, r: 8, p: 1, maxmem: 256 * 2 ** ln * 8 });
	return `$scrypt$ln=${ln},r=8,p=1$${toUnpaddedBase64(salt)}$${toUnpaddedBase64(key)}`;
}

/** A password of exactly 72 bytes in UTF-8, made of 3-byte characters. */
export const seventyTwoBytes = "\u3042".repeat(24);

export interface UsersHarness {
	/**
	 * Users holding "alice" with the password "correct horse", whose subject is "s-alice" and whose
	 * attributes are `{ name: "Alice", email: "Alice@example.com" }`, linked to the upstream identity
	 * "u-alice" at the IdP "example", and nothing else written.
	 */
	open(): Promise<Users>;
	/** Set where the settings fix no links (users answer from a user ledger): `open` writes the link to "u-alice". */
	readonly writtenLinksOnly?: boolean;
	/** Set where the user ledger cannot look users up by subject: every subject is unanswerable. */
	readonly unanswerableBySubject?: boolean;
	/** For implementations that read bcrypt: users holding "long", whose password is `seventyTwoBytes`. */
	openBcrypt?(): Promise<Users>;
	/**
	 * The same users, with the work of every password check recorded in order. Required: an
	 * implementation must show that an unknown user costs the same checks as a known one.
	 */
	openCounting(): Promise<{ readonly users: Users; readonly checks: readonly string[] }>;
}

/** The users contract, run against any implementation. */
export function usersContract(name: string, harness: UsersHarness): void {
	describe(`users contract: ${name}`, () => {
		it("finds a user by identifier and password, and hands over a frozen copy", async () => {
			const found = await (await harness.open()).verify("alice", "correct horse");
			expect(found.kind).toBe("user");
			if (found.kind !== "user") return;
			expect(found.user.subject).toBe("s-alice");
			expect(Object.isFrozen(found.user)).toBe(true);
			expect(Object.isFrozen(found.user.attributes)).toBe(true);
		});

		it("answers none alike for a wrong password, an unknown user and an empty identifier", async () => {
			const u = await harness.open();
			expect(await u.verify("alice", "wrong")).toEqual({ kind: "none" });
			expect(await u.verify("nobody", "correct horse")).toEqual({ kind: "none" });
			expect(await u.verify("", "correct horse")).toEqual({ kind: "none" });
		});

		it("does the same password checks for an unknown user as for a known one", async () => {
			const { users: u, checks } = await harness.openCounting();
			await u.verify("alice", "wrong");
			const known = [...checks];
			await u.verify("nobody", "wrong");
			expect(known.length).toBeGreaterThan(0);
			expect(checks.slice(known.length)).toEqual(known);
		});

		it.runIf(Boolean(harness.unanswerableBySubject))(
			"answers every subject and its claimed contacts unanswerable, never none",
			async () => {
				const u = await harness.open();
				for (const subject of ["s-alice", "alice", "s-nobody"]) {
					expect(await u.bySubject(subject), subject).toEqual({ kind: "unanswerable" });
				}
				expect(await u.claimedContacts("s-alice")).toEqual({ kind: "unanswerable" });
				const found = await u.byUpstream("example", "u-alice");
				expect(found).toEqual({ kind: "user", user: { subject: "s-alice", attributes: {} } });
			},
		);

		it.skipIf(Boolean(harness.unanswerableBySubject))(
			"finds a user by subject exactly, never by identifier, and hands over a frozen copy",
			async () => {
				const u = await harness.open();
				const found = await u.bySubject("s-alice");
				expect(found.kind === "user" && found.user.attributes).toEqual({
					name: "Alice",
					email: "Alice@example.com",
				});
				expect(found.kind === "user" && Object.isFrozen(found.user.attributes)).toBe(true);
				for (const subject of ["alice", "S-alice", "s-alic", "s-alice ", ""]) {
					expect(await u.bySubject(subject), subject).toEqual({ kind: "none" });
				}
			},
		);

		it.skipIf(Boolean(harness.unanswerableBySubject))(
			"states the email the user is known by as a claimed contact, exactly and apart from verified ones",
			async () => {
				const u = await harness.open();
				const claimed = [{ kind: "email", value: "Alice@example.com" }];
				expect(await u.claimedContacts("s-alice")).toEqual(claimed);
				expect(Object.isFrozen(await u.claimedContacts("s-alice"))).toBe(true);
				await u.verifiedContact("s-alice", { kind: "email", value: "other@example.com" });
				expect(await u.claimedContacts("s-alice")).toEqual(claimed);
				expect(await u.contactsOf("s-alice")).toEqual([
					{ kind: "email", value: "other@example.com" },
				]);
				expect(await u.claimedContacts("s-nobody")).toEqual([]);
				expect(await u.claimedContacts("")).toEqual([]);
			},
		);

		it("finds a user by an upstream identity exactly, never by a part of it", async () => {
			const u = await harness.open();
			const found = await u.byUpstream("example", "u-alice");
			expect(found.kind === "user" && found.user.subject).toBe("s-alice");
			expect(found.kind === "user" && Object.isFrozen(found.user)).toBe(true);
			for (const [idp, subject] of [
				["example", "u-other"],
				["other", "u-alice"],
				["Example", "u-alice"],
				["example:u", "alice"],
				["", "example:u-alice"],
				["example", ""],
			] as const) {
				expect(await u.byUpstream(idp, subject), `${idp} ${subject}`).toEqual({ kind: "none" });
			}
		});

		it("links an upstream identity only when asked, to one subject, and finds the user through the same read", async () => {
			const u = await harness.open();
			const added = { idp: "example", subject: "u-added" };
			expect(await u.byUpstream("example", "u-added")).toEqual({ kind: "none" });
			expect(await u.link("s-alice", added)).toBe("linked");
			expect(await u.byUpstream("example", "u-added")).toEqual(
				await u.byUpstream("example", "u-alice"),
			);
			expect(await u.link("s-alice", added)).toBe("already");
			expect(await u.link("s-bob", added)).toBe("conflict");
			for (const [idp, subject] of [
				["Example", "u-added"],
				["example", "u-adde"],
				["example:u", "added"],
			] as const) {
				expect(await u.byUpstream(idp, subject), `${idp} ${subject}`).toEqual({ kind: "none" });
			}
		});

		it("finds a written link's subject as the users answer it: none outweighs the link", async () => {
			const u = await harness.open();
			expect(await u.link("s-new", { idp: "other", subject: "u-new" })).toBe("linked");
			const found = await u.byUpstream("other", "u-new");
			// Only where the users cannot answer by subject does the link stand for its subject alone.
			const alone = { kind: "user", user: { subject: "s-new", attributes: {} } };
			expect(found).toEqual(harness.unanswerableBySubject ? alone : { kind: "none" });
			expect(found.kind !== "user" || Object.isFrozen(found.user.attributes)).toBe(true);
			expect(await u.link("s-alice", { idp: "other", subject: "u-alice" })).toBe("linked");
			const held = await u.byUpstream("other", "u-alice");
			expect(held.kind === "user" && held.user.subject).toBe("s-alice");
		});

		it.skipIf(Boolean(harness.writtenLinksOnly))(
			"never moves or removes a link the settings hold",
			async () => {
				const u = await harness.open();
				const fixed = { idp: "example", subject: "u-alice" };
				expect(await u.link("s-alice", fixed)).toBe("already");
				expect(await u.link("s-bob", fixed)).toBe("conflict");
				expect(await u.unlink("s-alice", fixed)).toBe("fixed");
				expect(await u.unlink("s-bob", fixed)).toBe("none");
				const found = await u.byUpstream("example", "u-alice");
				expect(found.kind === "user" && found.user.subject).toBe("s-alice");
			},
		);

		it("unlinks only the subject's own link, after which another subject may take it", async () => {
			const u = await harness.open();
			const upstream = { idp: "example", subject: "u-moved" };
			await u.link("s-alice", upstream);
			expect(await u.unlink("s-bob", upstream)).toBe("none");
			const kept = await u.byUpstream("example", "u-moved");
			expect(kept.kind === "user" && kept.user.subject).toBe("s-alice");
			expect(await u.unlink("s-alice", upstream)).toBe("unlinked");
			expect(await u.unlink("s-alice", upstream)).toBe("none");
			expect(await u.byUpstream("example", "u-moved")).toEqual({ kind: "none" });
			expect(await u.link("s-bob", upstream)).toBe("linked");
			expect(await u.link("s-alice", upstream)).toBe("conflict");
		});

		it("links an upstream identity to one subject when two ask at once", async () => {
			const u = await harness.open();
			const upstream = { idp: "example", subject: "u-raced" };
			const answers = await Promise.all([u.link("s-a", upstream), u.link("s-b", upstream)]);
			expect(answers.toSorted()).toEqual(["conflict", "linked"]);
		});

		it("refuses an empty part, an ill-formed subject or an unknown kind of contact instead of linking or keeping it", async () => {
			const u = await harness.open();
			for (const [subject, idp, upstream] of [
				["", "example", "u"],
				["s-é", "example", "u"],
				["s".repeat(256), "example", "u"],
				["s", "", "u"],
				["s", "example", ""],
			] as const) {
				await expect(u.link(subject, { idp, subject: upstream })).rejects.toBeInstanceOf(TypeError);
			}
			const email = { kind: "email", value: "a@example.com" } as const;
			await expect(u.verifiedContact("", email)).rejects.toBeInstanceOf(TypeError);
			await expect(u.verifiedContact("s", { kind: "email", value: "" })).rejects.toBeInstanceOf(
				TypeError,
			);
			const phone = { kind: "phone", value: "+1 555 0100" } as unknown as Contact;
			await expect(u.verifiedContact("s", phone)).rejects.toBeInstanceOf(TypeError);
		});

		it("keeps verified contacts per subject, each once by mail's form and as first given, and hands over a frozen copy", async () => {
			const u = await harness.open();
			expect(await u.contactsOf("s-alice")).toEqual([]);
			const email = (value: string) => ({ kind: "email", value }) as const;
			await u.verifiedContact("s-alice", email("alice@example.com"));
			await u.verifiedContact("s-alice", email("alice@example.com"));
			await u.verifiedContact("s-alice", email("Alice@example.com"));
			// The domain is compared in one form, the local part as given.
			await u.verifiedContact("s-alice", email("alice@EXAMPLE.com"));
			const held = await u.contactsOf("s-alice");
			expect(held).toEqual([email("alice@example.com"), email("Alice@example.com")]);
			expect(Object.isFrozen(held) && Object.isFrozen(held[0])).toBe(true);
			expect(await u.contactsOf("s-bob")).toEqual([]);
			await Promise.all([
				u.verifiedContact("s-bob", email("b1@example.com")),
				u.verifiedContact("s-bob", email("b2@example.com")),
			]);
			expect((await u.contactsOf("s-bob")).map((c) => c.value).toSorted()).toEqual([
				"b1@example.com",
				"b2@example.com",
			]);
		});

		it("keeps at most 20 contacts per subject, refusing another but not one it holds", async () => {
			const u = await harness.open();
			const email = (n: number) => ({ kind: "email", value: `c${n}@example.com` }) as const;
			for (let n = 1; n <= 20; n++) await u.verifiedContact("s-full", email(n));
			await expect(u.verifiedContact("s-full", email(21))).rejects.toBeInstanceOf(RangeError);
			await u.verifiedContact("s-full", email(20));
			expect(await u.contactsOf("s-full")).toEqual(
				Array.from({ length: 20 }, (_, i) => email(i + 1)),
			);
		});

		it.runIf(Boolean(harness.openBcrypt))(
			"matches a bcrypt hash up to 72 bytes and never past them",
			async () => {
				const u = await (harness.openBcrypt as () => Promise<Users>)();
				expect((await u.verify("long", seventyTwoBytes)).kind).toBe("user");
				expect((await u.verify("long", `${seventyTwoBytes}a`)).kind).toBe("none");
			},
		);
	});
}

export interface LedgerHarness {
	/**
	 * A user ledger holding "alice" with the password "correct horse" and the subject "s-alice", with
	 * every password comparison it does recorded in order, by the work it takes.
	 */
	open(): Promise<{ readonly ledger: Ledger; readonly checks: readonly string[] }>;
	readonly unanswerableBySubject?: boolean;
	/** Set where the ledger looks users up by upstream identity: the one it ties to alice. */
	readonly upstreamOfAlice?: { readonly idp: string; readonly subject: string };
}

/** The user ledger contract, run against any user ledger. */
export function ledgerContract(name: string, harness: LedgerHarness): void {
	describe(`user ledger contract: ${name}`, () => {
		it("verifies alice, and answers none for a wrong password or an unknown identifier", async () => {
			const { ledger } = await harness.open();
			const found = await ledger.verify("alice", "correct horse");
			expect(found.kind === "user" && found.user.subject).toBe("s-alice");
			expect(await ledger.verify("alice", "wrong")).toEqual({ kind: "none" });
			expect(await ledger.verify("nobody", "correct horse")).toEqual({ kind: "none" });
			const bySubject = await ledger.bySubject("s-alice");
			if (harness.unanswerableBySubject) {
				expect(bySubject).toEqual({ kind: "unanswerable" });
				return;
			}
			expect(bySubject.kind === "user" && bySubject.user.subject).toBe("s-alice");
			expect(await ledger.bySubject("s-nobody")).toEqual({ kind: "none" });
		});

		it.runIf(harness.upstreamOfAlice !== undefined)(
			"finds alice by the upstream identity it ties to her, and none for one it does not know",
			async () => {
				const { ledger } = await harness.open();
				const { idp, subject } = harness.upstreamOfAlice ?? { idp: "", subject: "" };
				const found = await ledger.byUpstream?.(idp, subject);
				expect(found?.kind === "user" && found.user.subject).toBe("s-alice");
				expect(await ledger.byUpstream?.(idp, `${subject}-nobody`)).toEqual({ kind: "none" });
			},
		);

		it("does the same comparisons for an unknown identifier as for a known one", async () => {
			const { ledger, checks } = await harness.open();
			await ledger.verify("alice", "wrong");
			const known = [...checks];
			expect(known.length).toBeGreaterThan(0);
			for (const [identifier, password] of [
				["nobody", "wrong"],
				["nobody", "correct horse"],
				["alice", "correct horse"],
			] as const) {
				const before = checks.length;
				await ledger.verify(identifier, password);
				expect(checks.slice(before), identifier).toEqual(known);
			}
		});
	});
}

/** A users section entry for a test. */
export function testUser(
	identifier: string,
	password: string,
	extra: Record<string, unknown> = {},
) {
	return { identifier, "password-hash": testPasswordHash(password), ...extra };
}

/** The users part of a test's configuration. */
export function usersConfig(registered: readonly ReturnType<typeof testUser>[]) {
	return { users: { registered } };
}

/** One of users' Store interfaces kept in memory, copying records as a store does, and a writer that can race the next update of a key. */
function memoryStore<T>() {
	const kept = new Map<string, T>();
	const races = new Map<string, (record: T) => T>();
	const copy = (record: T): T => structuredClone(record);
	const store: RecordStore<T> = {
		save: async (key, record) => {
			if (kept.has(key)) return "exists";
			kept.set(key, copy(record));
			return "created";
		},
		read: async (key) => {
			const record = kept.get(key);
			return record === undefined ? undefined : copy(record);
		},
		update: async (key, change) => {
			const read = kept.get(key);
			if (read === undefined) return undefined;
			const race = races.get(key);
			races.delete(key);
			// The change ran on what it read, then lost the race: it runs again on the other write.
			if (race) change(copy(read));
			const before = race ? race(copy(read)) : read;
			const after = change(copy(before))?.value ?? before;
			kept.set(key, copy(after));
			return { before: copy(before), after: copy(after) };
		},
	};
	const raceNextUpdate = (key: string, change: (record: T) => T) => {
		races.set(key, change);
	};
	return { store, raceNextUpdate };
}

/** users' store interfaces kept in memory, for tests that assemble users. */
export function memoryUsersStores() {
	const links = memoryStore<StoredLink>();
	const contacts = memoryStore<StoredContacts>();
	const module = defineModule({ name: "users-stores" }, (m) => [
		m.provide(linkStore).by(() => links.store),
		m.provide(contactStore).by(() => contacts.store),
	]);
	return { module, links, contacts };
}

/** A place that keeps one of users' kinds of record, as one implementation of its store interfaces offers it. */
export interface UsersStorePlace<T> {
	readonly records: RecordStore<T>;
	/** Moves the place's clock on. */
	advance(ms: number): void;
	/** Before the next update of `key` writes, another writer changes its record as given. */
	raceNextUpdate(key: string, change: (record: T) => T): void;
	/** Where answers can be lost: the next write takes effect, but its answer is lost. */
	readonly loseNextAnswer?: () => void;
	/** Where the place replicates: a replica takes over, keeping only what was confirmed. */
	readonly failover?: () => Promise<void>;
	/** Where the place can restart: it does, keeping only what it holds durably. */
	readonly restart?: () => Promise<void>;
	/** Where memory can run short: it does, keeping only what is kept from eviction. */
	readonly pressMemory?: () => Promise<void>;
	/** Where the place replicates: while on, replicas take nothing, so nothing read can be confirmed. */
	readonly stallReplicas?: (on: boolean) => void;
}

/**
 * What users needs from any implementation of one of its store interfaces: records kept whole and
 * once, changed only from what they hold, never ended, through faults.
 */
function recordTests<T>(open: () => Promise<UsersStorePlace<T>>): void {
	let n = 0;
	const fresh = () => `k-${++n}-${Math.random().toString(36).slice(2)}`;
	const held = (value: object) => value as unknown as T;
	const counted = (record: T) => (record as unknown as { n: number }).n;
	const plus = (record: T) => ({ value: held({ n: counted(record) + 1 }) });

	it("keeps a record whole and once per key, and reads it back", async () => {
		const { records } = await open();
		const key = fresh();
		const odd = held({ state: "unheard-of", nested: { list: [1, "two"] } });
		expect(await records.save(key, odd)).toBe("created");
		expect(await records.save(key, held({ n: 1 }))).toBe("exists");
		expect(await records.read(key)).toEqual(odd);
		expect(await records.update(key, () => undefined)).toEqual({ before: odd, after: odd });
		expect(await records.read(fresh())).toBeUndefined();
		expect(await records.update(fresh(), plus)).toBeUndefined();
	});

	it("changes a record only from what it holds, again after a racing writer", async () => {
		const place = await open();
		const key = fresh();
		await place.records.save(key, held({ n: 1 }));
		expect(await place.records.update(key, plus)).toEqual({
			before: held({ n: 1 }),
			after: held({ n: 2 }),
		});
		place.raceNextUpdate(key, (record) => held({ n: counted(record) * 10 }));
		expect(await place.records.update(key, plus)).toEqual({
			before: held({ n: 20 }),
			after: held({ n: 21 }),
		});
	});

	it("never ends a record, saved or changed", async () => {
		const place = await open();
		const [saved, changed] = [fresh(), fresh()];
		await place.records.save(saved, held({ n: 1 }));
		await place.records.save(changed, held({ n: 1 }));
		await place.records.update(changed, plus);
		place.advance(10 * 365 * 86_400_000);
		expect(await place.records.read(saved)).toEqual(held({ n: 1 }));
		expect(await place.records.read(changed)).toEqual(held({ n: 2 }));
	});

	it("keeps records through lost answers, a failover, a restart and memory pressure", async (context) => {
		const place = await open();
		const { loseNextAnswer: lose, failover, restart, pressMemory } = place;
		if (!lose || !failover || !restart || !pressMemory) return context.skip();
		const [saved, changed] = [fresh(), fresh()];
		lose();
		expect(await place.records.save(saved, held({ n: 1 }))).toBe("created");
		await place.records.save(changed, held({ n: 1 }));
		lose();
		expect((await place.records.update(changed, plus))?.after).toEqual(held({ n: 2 }));
		await failover();
		await restart();
		await pressMemory();
		expect(await place.records.read(saved)).toEqual(held({ n: 1 }));
		expect(await place.records.read(changed)).toEqual(held({ n: 2 }));
	});
}

/** What users needs from any implementation of its link store: records whose reads are confirmed. */
export function linkStoreContract(
	name: string,
	open: () => Promise<UsersStorePlace<StoredLink>>,
): void {
	describe(`users' link store: ${name}`, () => {
		recordTests(open);

		it("reads only what is confirmed", async (context) => {
			const place = await open();
			const { stallReplicas: stall } = place;
			if (!stall) return context.skip();
			const key = `confirmed-${Math.random().toString(36).slice(2)}`;
			await place.records.save(key, {} as StoredLink);
			stall(true);
			await expect(place.records.read(key)).rejects.toSatisfy(isUnavailable);
			stall(false);
			expect(await place.records.read(key)).toEqual({});
		});
	});
}

/** What users needs from any implementation of its contact store. */
export function contactStoreContract(
	name: string,
	open: () => Promise<UsersStorePlace<StoredContacts>>,
): void {
	describe(`users' contact store: ${name}`, () => recordTests(open));
}
