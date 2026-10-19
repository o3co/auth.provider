import { randomBytes } from "node:crypto";
import type { Cookies } from "@mod/cookies";
import { recordingLog } from "@mod/kernel/testing";
import { expect, it } from "vitest";
import { memoryTransactions } from "../../../test/stores.ts";
import { transactionOf } from "../../transactions/records.ts";
import { transactionsOver } from "../../transactions/transactions.ts";
import { heldOf, holding } from "../held.ts";

const jar: Cookies = { lookup: () => ({ kind: "absent" }), write: (name) => name };
const opened = () => {
	const clock = { now: 0 };
	const kept = memoryTransactions(() => 0);
	const transactions = transactionsOver({
		listings: kept.listings,
		log: recordingLog().log,
		store: kept.transactions,
		jar,
		random: (n) => randomBytes(n),
		clock: { now: () => clock.now },
		ttlMs: 60_000,
		attempts: 2,
	});
	const read = async (id: string) => heldOf(transactionOf(await kept.transactions.read(id)));
	return { clock, transactions, held: holding(transactions), read };
};

it("holds a binding only in a transaction still in use, ending the pass it began with", async () => {
	const { clock, transactions, held, read } = opened();
	const start = () => transactions.start({ subject: "sue", purpose: "enroll-login" });
	const [used, late, open] = [await start(), await start(), await start()];
	await transactions.take(used.id);
	expect(await held.hold(used.id, "p")).toBe(false);
	await held.bindingSent(open.id, { proof: "contact", sealed: "s" });
	await held.bindingPassed(open.id, "s", { kind: "code", pass: "x" });
	expect(await held.hold(open.id, "p")).toBe(true);
	expect(await read(open.id)).toEqual({ pending: "p", proved: true });
	clock.now = 60_000;
	expect(await held.hold(late.id, "p")).toBe(false);
});

it("keeps a binding proof's pass only over the challenge it answered, which it ends", async () => {
	const { transactions, held, read } = opened();
	const { id } = await transactions.start({ subject: "sue", purpose: "enroll-login" });
	await held.bindingSent(id, { proof: "contact", sealed: "s2" });
	const passed = { kind: "code", pass: "pass" };
	expect(await held.bindingPassed(id, "s1", passed)).toBe(false);
	expect(await held.bindingPassed(id, "s2", passed)).toBe(true);
	expect(await read(id)).toEqual({ bindingPassed: passed, proved: true });
});
