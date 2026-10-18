import type { Cookies } from "@mod/cookies";
import { testRequest } from "@mod/http/testing";
import { isUnavailable } from "@mod/kernel";
import { recordingLog } from "@mod/kernel/testing";
import { expect, it } from "vitest";
import { memoryTransactions } from "../../../test/stores.ts";
import type { TransactionStore } from "../../store.ts";
import type { Transaction } from "../records.ts";
import { transactionsOver } from "../transactions.ts";

const jar: Cookies = {
	read: () => undefined,
	lookup: () => ({ kind: "absent" }),
	write: (name) => name,
};
const random = (n: number) => new Uint8Array(n).map(() => Math.floor(Math.random() * 256));
/** Transactions of 60 seconds on the records stand-in, whose clock stands still: only deadlines end them. */
const opened = (store?: (kept: TransactionStore) => TransactionStore) => {
	const clock = { now: 0 };
	const kept = memoryTransactions(() => 0);
	const transactions = transactionsOver({
		listings: kept.listings,
		log: recordingLog().log,
		store: store?.(kept.transactions) ?? kept.transactions,
		jar,
		random,
		clock: { now: () => clock.now },
		ttlMs: 60_000,
		attempts: 2,
	});
	const start = () => transactions.start({ subject: "sue", purpose: "enroll-login" });
	return { clock, kept, transactions, start };
};

it("takes a transaction once, and never one gone, taken or past its deadline", async () => {
	const { clock, transactions, start } = opened();
	expect(await transactions.take("none")).toBe(false);
	const { id } = await start();
	expect(await transactions.take(id)).toBe(true);
	expect(await transactions.take(id)).toBe(false);
	const late = await start();
	clock.now = 60_000;
	expect(await transactions.take(late.id)).toBe(false);
});

it("finds no transaction for a request without the browser's cookie", async () => {
	const { transactions, start } = opened();
	expect(await transactions.find(testRequest(), (await start()).id)).toBeUndefined();
});

it("holds a binding only in a transaction still in use", async () => {
	const { clock, transactions, start } = opened();
	const [used, late, open] = [await start(), await start(), await start()];
	await transactions.take(used.id);
	expect(await transactions.hold(used.id, "p")).toBe(false);
	expect(await transactions.hold(open.id, "p")).toBe(true);
	clock.now = 60_000;
	expect(await transactions.hold(late.id, "p")).toBe(false);
});

it("keeps a binding proof's pass only over the challenge it answered, which it ends", async () => {
	const { kept, transactions, start } = opened();
	const { id } = await start();
	await transactions.bindingSent(id, { proof: "contact", sealed: "s2" });
	const passed = { kind: "code", pass: "pass" };
	expect(await transactions.bindingPassed(id, "s1", passed)).toBe(false);
	expect(await transactions.bindingPassed(id, "s2", passed)).toBe(true);
	const held = (await kept.transactions.read(id)) as unknown as Transaction;
	expect([held.bindingPassed, held.bindingChallenge]).toEqual([passed, undefined]);
});

it("holds or clears a challenge only in a transaction still in use", async () => {
	const { clock, transactions, start } = opened();
	const [used, late, open] = [await start(), await start(), await start()];
	const sent = { factor: "f", sealed: "s" };
	await transactions.take(used.id);
	expect([
		await transactions.challenged(used.id, sent),
		await transactions.challenged(used.id),
	]).toEqual([false, false]);
	expect(await transactions.challenged(open.id, sent)).toBe(true);
	expect(await transactions.spend(open.id)).toEqual({ left: 1, challenge: sent });
	expect(await transactions.spend(open.id)).toEqual({ left: 0, challenge: undefined });
	clock.now = 60_000;
	expect(await transactions.challenged(late.id)).toBe(false);
});

it("answers unavailable when a new transaction's key is held already", async () => {
	const { start } = opened((kept) => ({ ...kept, save: async () => "exists" }));
	await expect(start()).rejects.toSatisfy(isUnavailable);
});
