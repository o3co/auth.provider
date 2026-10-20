import type { Cookies } from "@mod/cookies";
import { testRequest } from "@mod/http/testing";
import { isUnavailable } from "@mod/kernel";
import { recordingLog } from "@mod/kernel/testing";
import { expect, it } from "vitest";
import { memoryTransactions } from "../../../test/stores.ts";
import type { TransactionStore } from "../../store.ts";
import { type Transaction, transactionOf } from "../records.ts";
import { transactionsOver } from "../transactions.ts";

const jar: Cookies = {
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

it("keeps what a transaction holds only while it is in use, changed from what it holds", async () => {
	const { clock, transactions, start } = opened();
	const [used, late, open] = [await start(), await start(), await start()];
	await transactions.take(used.id);
	expect(await transactions.keep(used.id, () => ({ n: 1 }))).toBeUndefined();
	expect(await transactions.keep(open.id, () => ({ n: 1 }))).toEqual({ held: { n: 1 } });
	const plus = (held: unknown) => ({ n: (held as { n: number }).n + 1 });
	expect(await transactions.keep(open.id, plus)).toEqual({ held: { n: 2 } });
	expect(await transactions.keep(open.id, () => undefined)).toBeUndefined();
	clock.now = 60_000;
	expect(await transactions.keep(late.id, () => ({ n: 1 }))).toBeUndefined();
});

it("starts a transaction holding what it is given, in format 2", async () => {
	const { kept, transactions } = opened();
	const { id } = await transactions.start({
		subject: "sue",
		purpose: "enroll-login",
		held: { pending: "p" },
	});
	const record = (await kept.transactions.read(id)) as unknown as Transaction;
	expect([record.format, record.held]).toEqual([2, { pending: "p" }]);
});

it("reads a format 1 record's binding fields as what it holds, wherever it is read", async () => {
	const { clock, kept, transactions, start } = opened();
	const { id } = await start();
	const binding = {
		pending: "p",
		bindingChallenge: { proof: "contact", sealed: "s" },
		bindingPassed: { kind: "code", pass: "x" },
		proved: true,
	};
	await kept.transactions.update(id, (record) => {
		const { format: _, held: __, ...rest } = record as unknown as Transaction;
		return { value: { ...rest, ...binding } as never };
	});
	// As find and every change read it: the binding's fields are what it holds, and the top keeps none.
	const read = transactionOf(await kept.transactions.read(id)) as Transaction &
		Record<string, unknown>;
	expect([read.format, read.held, read.pending, read.bindingChallenge]).toEqual([
		2,
		binding,
		undefined,
		undefined,
	]);
	clock.now = 1;
	expect(await transactions.keep(id, (held) => held)).toEqual({ held: binding });
	const written = (await kept.transactions.read(id)) as unknown as Record<string, unknown>;
	expect([written.format, written.pending, written.proved]).toEqual([2, undefined, undefined]);
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
