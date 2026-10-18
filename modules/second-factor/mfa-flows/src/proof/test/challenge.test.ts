import { randomBytes } from "node:crypto";
import type { AuditRecord } from "@mod/audit";
import type { Cookies } from "@mod/cookies";
import type { HttpRequest, HttpResponse } from "@mod/http";
import { testRequest } from "@mod/http/testing";
import { isUnavailable, Unavailable } from "@mod/kernel";
import type { Challenged, Factors } from "@mod/mfa";
import { expect, it } from "vitest";
import { memoryTransactions } from "../../../test/stores.ts";
import { transactionsOver } from "../../transactions/transactions.ts";
import { gateOver, proofOver } from "../proof.ts";

const carried = (request: HttpRequest, name: string) =>
	request.headers
		.get("cookie")
		?.split("; ")
		.find((c) => c.startsWith(`${name}=`))
		?.slice(name.length + 1);
const jar: Cookies = {
	read: carried,
	lookup: (request, name) => {
		const value = carried(request, name);
		return value === undefined ? { kind: "absent" } : { kind: "found", value };
	},
	write: (name, value) => `${name}=${value}`,
};

/** proof over stand-ins: one browser, a login held for the factor `mail`, and a challenge answer the test sets. */
async function proved() {
	const now = 1_000_000;
	const kept = memoryTransactions(() => now);
	const transactions = transactionsOver({
		store: kept.transactions,
		jar,
		random: (n) => new Uint8Array(randomBytes(n)),
		clock: { now: () => now },
		ttlMs: 600_000,
		attempts: 5,
	});
	const events: AuditRecord[] = [];
	const audit = { record: (event: AuditRecord) => void events.push(event) };
	let revoked = false;
	const asked: number[] = [];
	const judged: (string | undefined)[] = [];
	const next: { answer: () => Promise<Challenged> } = {
		answer: async () => ({
			kind: "sent",
			factorKind: "email",
			show: { to: "a***@example.com" },
			sealed: "one",
		}),
	};
	const factors: Pick<Factors, "asks" | "guessable" | "held" | "challenge" | "prove"> = {
		asks: async () => "proof",
		guessable: async (_subject, factor) => (["mail", "key"].includes(factor) ? false : undefined),
		held: async () => [],
		challenge: async (_subject, factor, until) => {
			asked.push(until);
			return factor === "mail" ? next.answer() : { kind: "unknown" };
		},
		prove: async (_subject, _factor, _proof, challenge) => {
			judged.push(challenge);
			return { kind: "invalid" };
		},
	};
	const proof = proofOver({
		permits: { grant: async () => {} },
		factors,
		sessions: {
			enter: async () => undefined,
			raise: async () => undefined,
			close: async () => ({ kind: "closed", cookies: [] }),
		},
		logins: { resume: async () => ({ kind: "held", gate: "x", answer: {}, cookies: [] }) },
		lockouts: {
			reserve: async () => ({ kind: "open", reservation: 1 }),
			succeeded: async () => {},
			abandoned: async () => {},
		},
		policy: {
			threshold: 5,
			backoffMs: 1,
			maxBackoffMs: 1,
			budget: 1,
			budgetWindowMs: 1,
			hardLimit: 1,
			memoryMs: 1,
		},
		revocation: { check: async () => (revoked ? "revoked" : "valid") },
		transactions,
		audit,
		log: { warn: () => {} },
		enrollmentChallenge: async () => {
			throw new Error("no enrollment here");
		},
	});
	const held = await gateOver({ factors, transactions })(
		testRequest(),
		{ subject: "sue", amr: ["pwd"], authenticatedAt: now },
		{},
	);
	if (held.kind !== "held") throw new Error("the login was not held");
	const tx = (held.answer as { transaction: string }).transaction;
	const cookie = held.cookies?.[0] ?? "";
	const post = (
		handle: (r: ReturnType<typeof testRequest>) => Promise<HttpResponse>,
		values: Record<string, string>,
		determined = true,
	) =>
		handle(
			testRequest({
				method: "POST",
				headers: new Map([["cookie", cookie]]),
				fields: new Map(
					Object.entries({ transaction_id: tx, ...values }).map(([k, v]) => [k, [v]]),
				),
				...(determined ? {} : { source: { determined: false } }),
			}),
		);
	const challenge = (factor = "mail") => post(proof.challenge, { factor_id: factor });
	const verify = (factor = "mail", determined = true) =>
		post(proof.verify, { factor_id: factor, proof: "123456" }, determined);
	return {
		next,
		asked,
		judged,
		events: () => events,
		challenge,
		verify,
		revoke: () => {
			revoked = true;
		},
		deadline: now + 600_000,
	};
}

const statusOf = (response: HttpResponse) => [
	response.status,
	(response.body as { json: unknown }).json,
];

it("keeps the challenge sent until the transaction's end, and gives it to the next proof once", async () => {
	const s = await proved();
	expect(statusOf(await s.challenge())).toEqual([200, { to: "a***@example.com" }]);
	expect(s.asked).toEqual([s.deadline]);
	await s.verify();
	await s.verify();
	expect(s.judged).toEqual(["one", undefined]);
});

it("gives a challenge only to a proof of the factor it was sent for, and voids it either way", async () => {
	const s = await proved();
	await s.challenge();
	await s.verify("key");
	await s.verify("mail");
	expect(s.judged).toEqual([undefined, undefined]);
});

it("voids the challenge before when another is asked, whatever comes of it", async () => {
	const s = await proved();
	await s.challenge();
	s.next.answer = async () => ({ kind: "sent", factorKind: "email", show: {}, sealed: "two" });
	await s.challenge();
	await s.verify();
	await s.challenge();
	s.next.answer = async () => ({ kind: "limited" });
	expect(statusOf(await s.challenge())).toEqual([429, { error: "rate_limited" }]);
	await s.verify();
	expect(s.judged).toEqual(["two", undefined]);
});

it("records a challenge sent with its kind; refuses a factor its kind will not send to, recording nothing more, and keeps nothing", async () => {
	const s = await proved();
	await s.challenge();
	s.next.answer = async () => ({ kind: "refused", factorKind: "email" });
	expect(statusOf(await s.challenge())).toEqual([403, { error: "mfa_factor_refused" }]);
	expect(s.events()).toEqual([
		expect.objectContaining({
			kind: "mfa.challenge.sent",
			subject: "sue",
			attributes: { kind: "email", purpose: "login", source: "127.0.0.1" },
		}),
	]);
	await s.verify();
	expect(s.judged).toEqual([undefined]);
});

it("voids the challenge before when the kind cannot tell, and the transaction goes on", async () => {
	const s = await proved();
	await s.challenge();
	s.next.answer = async () => {
		throw new Unavailable("mail");
	};
	await expect(s.challenge()).rejects.toSatisfy(isUnavailable);
	expect(statusOf(await s.verify())).toEqual([
		401,
		{ error: "mfa_invalid", attempts_remaining: 4 },
	]);
	expect(s.judged).toEqual([undefined]);
});

it("answers a factor that sends nothing with nothing, and an unknown one as unknown", async () => {
	const s = await proved();
	s.next.answer = async () => ({ kind: "none" });
	expect(statusOf(await s.challenge())).toEqual([200, {}]);
	expect(statusOf(await s.challenge("lost"))).toEqual([
		400,
		{ error: "invalid_request", error_description: "unknown factor" },
	]);
});

it("ends the transaction of a subject revoked since it started", async () => {
	const s = await proved();
	s.revoke();
	expect(statusOf(await s.challenge())).toEqual([401, { error: "login_required" }]);
	expect((await s.verify()).status).toBe(400);
	expect(s.asked).toEqual([]);
});

it("records a judged proof without a source that a trusted proxy did not determine", async () => {
	const s = await proved();
	await s.verify("mail", false);
	expect(s.events().map((e) => [e.kind, e.attributes])).toStrictEqual([
		["mfa.verify.failure", { purpose: "login", factor: "mail", reason: "invalid" }],
	]);
});

/** How the stand-in mail kind answers its next challenge; only the test below sets it. */
