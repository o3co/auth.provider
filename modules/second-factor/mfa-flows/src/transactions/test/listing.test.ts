import type { Cookies } from "@mod/cookies";
import type { HttpRequest } from "@mod/http";
import { testRequest } from "@mod/http/testing";
import { isUnavailable } from "@mod/kernel";
import { recordingLog } from "@mod/kernel/testing";
import { expect, it } from "vitest";
import { memoryTransactions } from "../../../test/stores.ts";
import { transactionsPerHolder } from "../../store.ts";
import type { Started } from "../records.ts";
import { transactionsOver } from "../transactions.ts";

/** A jar that hands back, as the request's cookie, what it wrote. */
const carried = (request: HttpRequest, name: string) =>
	request.headers
		.get("cookie")
		?.split("; ")
		.find((c) => c.startsWith(`${name}=`))
		?.slice(name.length + 1);
const jar: Cookies = {
	lookup: (request, name) => {
		const value = carried(request, name);
		return value === undefined ? { kind: "absent" } : { kind: "found", value };
	},
	write: (name, value) => `${name}=${value}`,
};
const random = (n: number) => new Uint8Array(n).map(() => Math.floor(Math.random() * 256));

/** Transactions of 60 seconds whose clock the test moves; each start a millisecond after the last. */
function opened() {
	const clock = { now: 0 };
	const kept = memoryTransactions(() => clock.now);
	const logged = recordingLog();
	const transactions = transactionsOver({
		store: kept.transactions,
		listings: kept.listings,
		jar,
		log: logged.log,
		random,
		clock: { now: () => clock.now },
		ttlMs: 60_000,
		attempts: 2,
	});
	const start = async (started: Started) => {
		clock.now += 1;
		const { id, cookies } = await transactions.start(started);
		const request = testRequest({ headers: new Map([["cookie", cookies[0] as string]]) });
		return { id, found: async () => (await transactions.find(request, id)) !== undefined };
	};
	return { kept, logged, transactions, start };
}

const login = { subject: "sue", purpose: "enroll-login" } as const;

it(`keeps ${transactionsPerHolder} live transactions a holder: one more ends the one ending first`, async () => {
	const { start } = opened();
	const first = await start(login);
	const rest = [];
	for (let n = 1; n < transactionsPerHolder; n++) rest.push(await start(login));
	expect(await first.found()).toBe(true);
	const last = await start(login);
	expect(await first.found()).toBe(false);
	for (const kept of [...rest, last]) expect(await kept.found()).toBe(true);
});

it("counts a session's transactions apart from a held login's, and one subject's apart from another's", async () => {
	const { start } = opened();
	const held = await start(login);
	for (let n = 0; n < transactionsPerHolder; n++) {
		await start({ subject: "sue", purpose: "step-up", handle: "h1" });
		await start({ subject: "tom", purpose: "enroll-login" });
	}
	expect(await held.found()).toBe(true);
});

it("counts no transaction once taken or out of attempts, so it pushes out none", async () => {
	const { transactions, start } = opened();
	const taken = await start(login);
	const spent = await start(login);
	const first = await start(login);
	expect(await transactions.take(taken.id)).toBe(true);
	await transactions.spend(spent.id);
	await transactions.spend(spent.id);
	for (let n = 3; n < transactionsPerHolder + 2; n++) await start(login);
	expect(await first.found()).toBe(true);
});

it("starts and finds nothing while the listing cannot answer, and logs a removal it cannot make", async () => {
	const { kept, logged, transactions, start } = opened();
	const listed = await start(login);
	kept.listingsDown.failNext("members");
	await expect(listed.found()).rejects.toSatisfy(isUnavailable);
	kept.listingsDown.failNext("add");
	await expect(start(login)).rejects.toSatisfy(isUnavailable);
	kept.listingsDown.failNext("remove");
	expect(await transactions.take(listed.id)).toBe(true);
	expect(logged.lines().map((line) => line.event)).toEqual(["mfa-flows.listing_failed"]);
});
