import { randomBytes } from "node:crypto";
import type { Cookies } from "@mod/cookies";
import type { HttpRequest, HttpResponse } from "@mod/http";
import { testRequest } from "@mod/http/testing";
import { isUnavailable, Unavailable } from "@mod/kernel";
import { recordingLog } from "@mod/kernel/testing";
import type { LoginOutcome } from "@mod/login-gates";
import type { Reserved } from "@mod/rate-limit";
import type { Session } from "@mod/session";
import { expect, it } from "vitest";
import { memoryTransactions } from "../../../test/stores.ts";
import type { Started } from "../../transactions/records.ts";
import { transactionsOver } from "../../transactions/transactions.ts";
import { proofOver } from "../proof.ts";

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
const session: Session = { id: "h1", context: { subject: "sue", amr: ["pwd"] } as never };
const opened: LoginOutcome = { kind: "opened", session, cookies: ["session=s1"] };

/** proof over stand-ins whose answers a test sets; `calls` lists what reached the parts. */
function standIn() {
	let now = 1_000_000;
	const kept = memoryTransactions(() => now);
	const transactions = transactionsOver({
		listings: kept.listings,
		log: recordingLog().log,
		store: kept.transactions,
		jar,
		random: (n) => new Uint8Array(randomBytes(n)),
		clock: { now: () => now },
		ttlMs: 600_000,
		attempts: 5,
	});
	const calls: string[] = [];
	const logged = recordingLog();
	const set = {
		reserved: { kind: "open", reservation: 1 } as Reserved,
		raise: { session, cookies: ["session=s2"], raised: true } as
			| { session: Session; cookies: string[]; raised: boolean }
			| undefined,
		resumed: opened,
		revoked: false,
		/** The revocation lands while the login opens. */
		revokeOnOpen: false,
		entered: session as Session | undefined,
		held: [{ id: "f", kind: "code" }],
	};
	const proof = proofOver({
		permits: { grant: async () => {} },
		factors: {
			guessable: async () => true,
			held: async () => set.held,
			challenge: async (_subject, _factor, _until, from) => {
				calls.push(`challenge ${JSON.stringify(from)}`);
				return { kind: "none" };
			},
			prove: async (_subject, _factor, given) => {
				if (given === "unreadable") throw new Unavailable("mfa");
				if (given === "broken") throw new TypeError("mfa");
				return given === "right" ? { kind: "valid", amr: ["otp"] } : { kind: "invalid" };
			},
		},
		sessions: {
			enter: async () => set.entered,
			raise: async () => set.raise,
			close: async (id) => {
				calls.push(`close ${id}`);
				return { kind: "closed", cookies: [] };
			},
		},
		logins: {
			resume: async (_request, facts) => {
				calls.push(`resume ${facts.amr.join(" ")}`);
				set.revoked ||= set.revokeOnOpen;
				return set.resumed;
			},
		},
		lockouts: {
			reserve: async () => set.reserved,
			succeeded: async () => void calls.push("succeeded"),
			abandoned: async () => void calls.push("abandoned"),
		},
		policy: {
			threshold: 5,
			backoffMs: 1,
			maxBackoffMs: 1,
			budget: 5,
			budgetWindowMs: 1,
			hardLimit: 5,
			memoryMs: 1,
		},
		revocation: { check: async () => (set.revoked ? "revoked" : "valid") },
		transactions,
		audit: { record: () => {} },
		log: logged.log,
		enrollmentChallenge: async () => ({ status: 299, headers: {}, body: { json: {} } }),
	});
	/** A transaction of this purpose, and how a POST or a GET names it from its browser. */
	const begun = async (record: Started) => {
		const { id, cookies } = await transactions.start(record);
		const cookie = cookies[0] ?? "";
		const request = (values: Record<string, string> = {}, method: "GET" | "POST" = "POST") =>
			testRequest({
				method,
				headers: new Map([
					["cookie", cookie],
					["mfa-transaction", id],
				]),
				fields: new Map(
					Object.entries({ transaction_id: id, ...values }).map(([k, v]) => [k, [v]]),
				),
			});
		return { id, request };
	};
	const login = () =>
		begun({ subject: "sue", purpose: "login", facts: { subject: "sue", amr: ["pwd"] } });
	return {
		set,
		calls,
		logged,
		kept,
		proof,
		begun,
		login,
		later: (ms: number) => {
			now += ms;
		},
	};
}

const statusOf = (response: HttpResponse) => [
	response.status,
	(response.body as { json: unknown }).json,
];
const right = { factor_id: "f", proof: "right" };

it("answers a held subject with when to come back, in whole seconds rounded up, or without when none is known", async () => {
	const s = standIn();
	const { request } = await s.login();
	s.set.reserved = { kind: "held", hold: "backoff", retryAfterMs: 1500 };
	expect((await s.proof.verify(request(right))).headers?.["retry-after"]).toBe("2");
	s.set.reserved = { kind: "held", hold: "hard" };
	expect((await s.proof.verify(request(right))).headers).not.toHaveProperty("retry-after");
});

it("settles a passing proof's reservation once, by handing it back as a success", async () => {
	const s = standIn();
	const { request } = await s.login();
	expect((await s.proof.verify(request(right))).status).toBe(200);
	expect(s.calls.filter((c) => c === "succeeded" || c === "abandoned")).toEqual(["succeeded"]);
});

it("goes on with a login by the facts and the proof's amr, answering what it held, and ends the binding", async () => {
	const s = standIn();
	const { request } = await s.begun({
		subject: "sue",
		purpose: "login",
		facts: { subject: "sue", amr: ["pwd"] },
		done: { redirect_to: "https://app.example/" },
	});
	const passed = await s.proof.verify(request(right));
	expect(statusOf(passed)).toEqual([200, { redirect_to: "https://app.example/" }]);
	expect(passed.cookies).toEqual(["session=s1", "mfa="]);
	expect(s.calls).toContain("resume pwd otp");
});

it("hands back the answer of a later gate that holds the login, with its cookies", async () => {
	const s = standIn();
	const { request } = await s.login();
	s.set.resumed = { kind: "held", gate: "later", answer: { step: "next" }, cookies: ["later=1"] };
	const held = await s.proof.verify(request(right));
	expect([...statusOf(held), held.cookies]).toEqual([403, { step: "next" }, ["later=1"]]);
});

it("refuses a login whose resume came past its caller's deadline as a gate would, logging it", async () => {
	const s = standIn();
	const { request } = await s.login();
	s.set.resumed = { kind: "expired" } as unknown as LoginOutcome;
	const expired = await s.proof.verify(request(right));
	expect([...statusOf(expired), expired.cookies]).toEqual([
		403,
		{ error: "login_required" },
		undefined,
	]);
	expect(s.logged.lines().map((l) => [l.level, l.event])).toEqual([
		["warn", "mfa-flows.login_expired"],
	]);
});

it("closes a session that opened after a revocation since the transaction started", async () => {
	const s = standIn();
	const { request } = await s.login();
	s.set.revokeOnOpen = true;
	const closed = await s.proof.verify(request(right));
	expect([...statusOf(closed), closed.cookies]).toEqual([
		401,
		{ error: "login_required" },
		["mfa="],
	]);
	expect(s.calls.at(-1)).toBe("close h1");
});

it("answers a step-up whose session went before the raise 401, one whose raise was not written 503, and clears the binding only once raised", async () => {
	const s = standIn();
	const stepUp = () => s.begun({ subject: "sue", purpose: "step-up", handle: "h1" });
	s.set.raise = undefined;
	expect(statusOf(await s.proof.verify((await stepUp()).request(right)))).toEqual([
		401,
		{ error: "login_required" },
	]);
	s.set.raise = { session, cookies: ["session=s2"], raised: false };
	const unwritten = await s.proof.verify((await stepUp()).request(right));
	expect([unwritten.status, unwritten.cookies]).toEqual([503, ["session=s2"]]);
	s.set.raise = { session, cookies: ["session=s2"], raised: true };
	const raised = await s.proof.verify((await stepUp()).request(right));
	expect([raised.status, raised.cookies]).toEqual([200, ["session=s2", "mfa="]]);
});

it("starts no step-up without a session, or for a subject holding no factor", async () => {
	const s = standIn();
	const post = testRequest({ method: "POST" });
	s.set.entered = undefined;
	expect(statusOf(await s.proof.stepUp(post))).toEqual([401, { error: "login_required" }]);
	s.set.entered = session;
	s.set.held = [];
	expect(statusOf(await s.proof.stepUp(post))).toEqual([
		403,
		{ error: "mfa_no_qualifying_factor" },
	]);
});

it("verifies no factor in an enrollment's transaction, and hands a challenge in a login's first enrollment to enrollment", async () => {
	const s = standIn();
	const { request } = await s.begun({ subject: "sue", purpose: "enroll-login" });
	expect((await s.proof.verify(request(right))).status).toBe(400);
	expect((await s.proof.challenge(request())).status).toBe(299);
});

it("gives back the attempt of a proof that cannot be judged, and never one a fault cut short", async () => {
	const s = standIn();
	const { request } = await s.login();
	const left = async () =>
		(statusOf(await s.proof.transaction(request({}, "GET")))[1] as { attempts_remaining: number })
			.attempts_remaining;
	const proving = (proof: string) => s.proof.verify(request({ factor_id: "f", proof }));
	await expect(proving("unreadable")).rejects.toSatisfy(isUnavailable);
	expect(await left()).toBe(5);
	await expect(proving("broken")).rejects.toThrow(TypeError);
	expect(await left()).toBe(4);
});

it("answers a transaction's time left in whole seconds, rounded down", async () => {
	const s = standIn();
	const { request } = await s.login();
	s.later(500);
	expect(statusOf(await s.proof.transaction(request({}, "GET")))[1]).toMatchObject({
		expires_in: 599,
	});
});

it("holds no challenge in a transaction ended while it was asked", async () => {
	const s = standIn();
	const { id, request } = await s.login();
	s.kept.beforeNextUpdate(async () => {
		await s.kept.transactions.update(id, (record) => ({
			value: { ...record, taken: true } as never,
		}));
	});
	expect((await s.proof.challenge(request({ factor_id: "f" }))).status).toBe(400);
});

it("asks a factor's challenge for a held login by the email its login gave, and for a step-up by its session", async () => {
	const s = standIn();
	const facts = {
		subject: "sue",
		amr: ["pwd"],
		attributes: { source: "users", values: { email: "sue@example.com" } },
	};
	const login = await s.begun({ subject: "sue", purpose: "login", facts });
	await s.proof.challenge(login.request({ factor_id: "f" }));
	const stepUp = await s.begun({ subject: "sue", purpose: "step-up", handle: "h1" });
	await s.proof.challenge(stepUp.request({ factor_id: "f" }));
	expect(s.calls.filter((call) => call.startsWith("challenge "))).toEqual([
		`challenge ${JSON.stringify({ kind: "login", email: "sue@example.com", vouched: true })}`,
		`challenge ${JSON.stringify({ kind: "session", handle: "h1" })}`,
	]);
});
