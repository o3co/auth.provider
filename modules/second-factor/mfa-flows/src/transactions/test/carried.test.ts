import type { Cookies } from "@mod/cookies";
import type { HttpRequest } from "@mod/http";
import { testRequest } from "@mod/http/testing";
import { recordingLog } from "@mod/kernel/testing";
import { expect, it } from "vitest";
import { memoryTransactions } from "../../../test/stores.ts";
import { transactionsOver } from "../transactions.ts";

/** A jar that reads the request's `mfa` cookie as it was written. */
const jar: Cookies = {
	lookup: (request: HttpRequest, name: string) => {
		const value = request.headers
			.get("cookie")
			?.split("; ")
			.find((c) => c.startsWith(`${name}=`))
			?.slice(name.length + 1);
		return value === undefined ? { kind: "absent" } : { kind: "found", value };
	},
	write: (name, value) => `${name}=${value}`,
};
const random = (n: number) => new Uint8Array(n).map(() => Math.floor(Math.random() * 256));
const transactions = () => {
	const kept = memoryTransactions(() => 0);
	return transactionsOver({
		store: kept.transactions,
		listings: kept.listings,
		jar,
		log: recordingLog().log,
		random,
		clock: { now: () => 0 },
		ttlMs: 60_000,
		attempts: 2,
	});
};
const withCookie = (value: string) =>
	testRequest({ headers: new Map([["cookie", `mfa=${value}`]]) });
const written = (cookie: string | undefined) => String(cookie).slice("mfa=".length);

it("names the transaction in the browser's cookie, beside the browser's secret", async () => {
	const t = transactions();
	const { id, cookies } = await t.start({ subject: "sue", purpose: "login" });
	const request = withCookie(written(cookies[0]));
	expect(t.carried(request)).toBe(id);
	expect((await t.find(request, id))?.transaction.subject).toBe("sue");
});

it("reads a cookie of the earlier form, the secret alone, naming no transaction", async () => {
	const t = transactions();
	const { id, cookies } = await t.start({ subject: "sue", purpose: "login" });
	const secret = written(cookies[0]).slice(id.length + 1);
	const request = withCookie(secret);
	expect(t.carried(request)).toBeUndefined();
	expect((await t.find(request, id))?.transaction.subject).toBe("sue");
});

it("reads a cookie with an empty part or more than one dot as no cookie, without throwing", async () => {
	const t = transactions();
	const { id, cookies } = await t.start({ subject: "sue", purpose: "login" });
	const secret = written(cookies[0]).slice(id.length + 1);
	for (const value of [`${id}.`, `.${secret}`, `${id}.${secret}.x`, `${id}..${secret}`, "."]) {
		const request = withCookie(value);
		expect(t.carried(request), value).toBeUndefined();
		expect(await t.find(request, id), value).toBeUndefined();
	}
});

it("names nothing for a request without the cookie", () => {
	expect(transactions().carried(testRequest())).toBeUndefined();
});
