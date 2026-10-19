import { type Cookies, cookies } from "@mod/cookies";
import type { HttpRequest } from "@mod/http";
import { type BuildContext, type Clock, isUnavailable, type Log, Unavailable } from "@mod/kernel";
import type { AskedFrom } from "@mod/mfa-extensions";
import { vouches } from "@mod/subject-attributes";
import type { Settings } from "../section.ts";
import {
	type TransactionListings,
	type TransactionStore,
	transactionListings,
	transactionStore,
} from "../store.ts";
import {
	type ByPurpose,
	type Challenge,
	hashOf,
	holderOf,
	live,
	type Started,
	stored,
	type Transaction,
	transactionOf,
	unchallenged,
} from "./records.ts";

/** Whom `mfa`'s kinds are asked for: a held login by the email its login gave, else the session. */
export const askedFrom = (t: ByPurpose): AskedFrom => {
	if ("handle" in t) return { kind: "session", handle: t.handle };
	const attributes = t.facts?.attributes;
	const email = attributes?.values.email;
	if (attributes === undefined || email === undefined) return { kind: "login" };
	return vouches(attributes) ? { kind: "login", email, vouched: true } : { kind: "login", email };
};

export interface TransactionParts {
	readonly store: TransactionStore;
	/** Each holder's live transactions; one counts only while listed. */
	readonly listings: TransactionListings;
	readonly jar: Cookies;
	readonly log: Log;
	readonly random: (n: number) => Uint8Array;
	readonly clock: Clock;
	/** The package's `transaction-lifetime`, in ms. */
	readonly ttlMs: number;
	/** The package's `attempts-per-transaction`. */
	readonly attempts: number;
}

export type Transactions = ReturnType<typeof transactionsOver>;

/** The transactions over the contracts the assembly gives and the package's section. */
export const transactionsIn = async (c: BuildContext<Settings>) =>
	transactionsOver({
		store: await c.get(transactionStore),
		listings: await c.get(transactionListings),
		jar: await c.get(cookies),
		log: c.log,
		random: c.random.bytes,
		clock: c.clock,
		ttlMs: c.section["transaction-lifetime"] * 1000,
		attempts: c.section["attempts-per-transaction"],
	});

export function transactionsOver(parts: TransactionParts) {
	const { store, listings, jar, random, clock, ttlMs, attempts } = parts;
	/** Whether the transaction is still among its holder's live ones; a listing that cannot tell throws. */
	const listed = async (id: string, t: Transaction) =>
		(await listings.members(holderOf(t))).some(({ member }) => member === hashOf(id));
	/** Takes a used transaction off its holder's listing; one that cannot be is logged and passed, as it ends at its lifetime. */
	const unlist = async (id: string, t: Transaction | undefined) => {
		if (!t) return;
		try {
			await listings.remove(holderOf(t), hashOf(id));
		} catch (error) {
			parts.log.warn("mfa-flows.listing_failed", {
				step: "remove",
				kind: error instanceof Error ? error.name : typeof error,
			});
		}
	};
	const text = (n: number) => Buffer.from(random(n)).toString("base64url");
	/** Changes a transaction still in use; one gone, taken or past its deadline is left as it is. */
	const changeLive = async (id: string, change: (t: Transaction) => Transaction | undefined) => {
		const now = clock.now();
		let applied = false;
		const changed = await store.update(id, (record) => {
			const t = transactionOf(record);
			const next = t && live(t, now) ? change(t) : undefined;
			applied = next !== undefined;
			return next && { value: stored(next) };
		});
		return {
			before: transactionOf(changed?.before),
			after: transactionOf(changed?.after),
			applied: applied && changed !== undefined,
		};
	};
	return {
		/** Starts a transaction bound to this browser by a cookie of mfa's own. */
		start: async (record: Started) => {
			const id = text(32);
			const browser = text(32);
			const now = clock.now();
			const value = {
				...record,
				format: 2 as const,
				attemptsLeft: attempts,
				browser: hashOf(browser),
				startedAt: now,
				deadline: now + ttlMs,
			};
			const saved = await store.save(id, stored(value), ttlMs);
			if (saved !== "created") throw new Unavailable("mfa-flows");
			// Listed after it is kept, so a listed one is always found; past the cap the one ending first leaves.
			await listings.add(holderOf(value), hashOf(id), ttlMs);
			return {
				id,
				deadline: value.deadline,
				expiresIn: Math.floor(ttlMs / 1000),
				cookies: [jar.write("mfa", browser, Math.floor(ttlMs / 1000))],
			};
		},
		/** The deadline of a transaction started now; one started later ends no sooner. */
		nextDeadline: () => clock.now() + ttlMs,
		/** The transaction, only for the browser that started it, while it is in use. */
		find: async (request: HttpRequest, id: string | undefined) => {
			const carried = jar.lookup(request, "mfa");
			const browser = carried.kind === "found" ? carried.value : undefined;
			if (!id || !browser) return undefined;
			const found = transactionOf(await store.read(id));
			const now = clock.now();
			if (!found || !live(found, now) || found.browser !== hashOf(browser)) return undefined;
			if (!(await listed(id, found))) return undefined;
			return { transaction: found, leftMs: found.deadline - now };
		},
		/**
		 * Spends one attempt and takes the challenge with it; the attempts left and the challenge
		 * taken, or nothing when the transaction is gone or spent.
		 */
		spend: async (id: string) => {
			const { before, after } = await changeLive(id, (t) =>
				t.attemptsLeft > 0 ? { ...unchallenged(t), attemptsLeft: t.attemptsLeft - 1 } : undefined,
			);
			if (!before || !after || after.attemptsLeft >= before.attemptsLeft) return undefined;
			if (after.attemptsLeft === 0) await unlist(id, after);
			return { left: after.attemptsLeft, challenge: before.challenge };
		},
		/** Judges a proof on an attempt spent; one that cannot be judged (unavailable) gives the attempt back. */
		judged: async <T>(id: string, judge: () => Promise<T>) => {
			try {
				return await judge();
			} catch (error) {
				if (isUnavailable(error)) {
					await changeLive(id, (t) => ({ ...t, attemptsLeft: t.attemptsLeft + 1 }));
				}
				throw error;
			}
		},
		/** Takes the transaction; true only for the one request that took it. */
		take: async (id: string) => {
			const { before, after } = await changeLive(id, (t) => ({ ...t, taken: true }));
			const took = !before?.taken && after?.taken === true;
			if (took) await unlist(id, after);
			return took;
		},
		/** Holds the challenge sent, or none; false when the transaction is no longer in use. */
		challenged: async (id: string, challenge?: Challenge) => {
			const changed = await changeLive(id, (t) =>
				challenge ? { ...t, challenge } : unchallenged(t),
			);
			return changed.applied;
		},
		/**
		 * Changes what the transaction holds, from what it holds: what it holds now, or none when it is
		 * no longer in use or the change gives nothing.
		 */
		keep: async (id: string, change: (held: unknown) => unknown) => {
			const changed = await changeLive(id, (t) => {
				const held = change(t.held);
				return held === undefined ? undefined : { ...t, held };
			});
			return changed.applied ? { held: changed.after?.held } : undefined;
		},
		cleared: () => jar.write("mfa", "", 0),
	};
}
