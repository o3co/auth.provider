import { type Cookies, cookies } from "@mod/cookies";
import type { HttpRequest } from "@mod/http";
import { type BuildContext, type Clock, isUnavailable, Unavailable } from "@mod/kernel";
import type { AskedFrom } from "@mod/mfa";
import { vouches } from "@mod/subject-attributes";
import type { Settings } from "../section.ts";
import { type TransactionStore, transactionStore } from "../store.ts";
import {
	type BindingChallenge,
	type ByPurpose,
	type Challenge,
	hashOf,
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
	readonly jar: Cookies;
	readonly random: (n: number) => Uint8Array;
	readonly clock: Clock;
	/** The package's `transaction-seconds`, in ms. */
	readonly ttlMs: number;
	/** The package's `attempts-per-transaction`. */
	readonly attempts: number;
}

export type Transactions = ReturnType<typeof transactionsOver>;

/** The transactions over the contracts the assembly gives and the package's section. */
export const transactionsIn = async (c: BuildContext<Settings>) =>
	transactionsOver({
		store: await c.get(transactionStore),
		jar: await c.get(cookies),
		random: c.random.bytes,
		clock: c.clock,
		ttlMs: c.section["transaction-seconds"] * 1000,
		attempts: c.section["attempts-per-transaction"],
	});

export function transactionsOver({ store, jar, random, clock, ttlMs, attempts }: TransactionParts) {
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
				attemptsLeft: attempts,
				browser: hashOf(browser),
				startedAt: now,
				deadline: now + ttlMs,
			};
			const saved = await store.save(id, stored(value), ttlMs);
			if (saved !== "created") throw new Unavailable("mfa-flows");
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
			const browser = jar.read(request, "mfa");
			if (!id || !browser) return undefined;
			const found = transactionOf(await store.read(id));
			const now = clock.now();
			if (!found || !live(found, now) || found.browser !== hashOf(browser)) return undefined;
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
			return before && after && after.attemptsLeft < before.attemptsLeft
				? { left: after.attemptsLeft, challenge: before.challenge }
				: undefined;
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
			return !before?.taken && after?.taken === true;
		},
		/** Holds the challenge sent, or none; false when the transaction is no longer in use. */
		challenged: async (id: string, challenge?: Challenge) => {
			const changed = await changeLive(id, (t) =>
				challenge ? { ...t, challenge } : unchallenged(t),
			);
			return changed.applied;
		},
		/** Holds the binding proof's challenge sent; false when the transaction is no longer in use. */
		bindingSent: async (id: string, bindingChallenge: BindingChallenge) =>
			(await changeLive(id, (t) => ({ ...t, bindingChallenge }))).applied,
		/** Keeps the binding proof's pass, only while the challenge it answered is the one held. */
		bindingPassed: async (id: string, sealed: string, passed: { kind: string; pass: string }) =>
			(
				await changeLive(id, ({ bindingChallenge, ...t }) =>
					bindingChallenge?.sealed === sealed
						? { ...t, bindingPassed: passed, proved: true }
						: undefined,
				)
			).applied,
		/** Holds a binding begun in the transaction, ending the pass it began with; false when it is no longer in use. */
		hold: async (id: string, pending: string) =>
			(await changeLive(id, ({ bindingPassed: _, ...t }) => ({ ...t, pending }))).after?.pending ===
			pending,
		cleared: () => jar.write("mfa", "", 0),
	};
}
