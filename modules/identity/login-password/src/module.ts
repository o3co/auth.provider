import { createHash } from "node:crypto";
import { audit, declaredAudit } from "@mod/audit";
import { csrfChecked } from "@mod/csrf";
import { type HttpRequest, type HttpResponse, noStore, routes, use } from "@mod/http";
import { defineModule, isUnavailable, setting } from "@mod/kernel";
import { loginSource } from "@mod/login-attributes";
import { amrSources, logins } from "@mod/login-gates";
import { attemptsPerSource, type LockoutPolicy, lockoutProblem, lockouts } from "@mod/rate-limit";
import { determinedSource } from "@mod/request-source";
import { acceptedAttributes, type User, users } from "@mod/users";
import { z } from "zod";
import events from "./audit-events.ts";

/** A key named before its unit was written: read in place of its new name while its writers move. */
const before = (min: number, max: number, instead: string) =>
	z.number().int().min(min).max(max).optional().describe(`Seconds; write \`${instead}\` instead.`);

const section = z.strictObject({
	attempts: z
		.number()
		.int()
		.min(1)
		.max(100)
		.prefault(20)
		.describe(
			"Login attempts allowed per source in each window, within bounds that keep guessing slow.",
		),
	window: setting
		.duration("s")
		.pipe(z.number().int().min(60).max(86_400))
		.prefault("15m")
		.describe("The window `attempts` is counted over, from 1m to 1d."),
	"account-attempts": z
		.number()
		.int()
		.min(1)
		.max(100)
		.prefault(10)
		.describe(
			"Failed attempts allowed at one identifier, from any source, before each next one waits.",
		),
	"account-window": setting
		.duration("s")
		.pipe(z.number().int().min(60).max(86_400))
		.prefault("1h")
		.describe("How long an identifier's run of failed attempts is remembered, from 1m to 1d."),
	"account-max-wait": setting
		.duration("s")
		.pipe(z.number().int().min(1).max(3600))
		.prefault("5m")
		.describe(
			"The longest an identifier waits between attempts, from 1s to 1h: the wait doubles to it, never locking out.",
		),
	"window-seconds": before(60, 86_400, "window"),
	"account-window-seconds": before(60, 86_400, "account-window"),
	"account-max-wait-seconds": before(1, 3600, "account-max-wait"),
});

/** The name an identifier's attempts are kept under. */
const accountAttempts = "login-password.account";

/**
 * An identifier's key: folded wider than users matches, so spellings a ledger may take alike share
 * one count, and hashed, so no identifier is kept.
 */
const accountKey = (identifier: string) =>
	createHash("sha256").update(identifier.normalize("NFKC").toLowerCase()).digest("base64url");

/** A JSON answer that is never cached, setting the cookies given. */
const answer = (status: number, json: unknown, cookies?: readonly string[]): HttpResponse => ({
	status,
	headers: noStore,
	body: { json },
	...(cookies ? { cookies } : {}),
});

/** What a password login proves. */
const proves: readonly string[] = ["pwd"];

/** The user's attributes as users accepts them, as session keeps them; session applies the caps. */
const attributesOf = (user: User) => ({
	source: loginSource.users,
	values: acceptedAttributes(user.attributes),
});

export default defineModule({ name: "login-password", section }, (m) => [
	m.contribute(amrSources).by(() => ({ name: "login-password", amr: proves })),
	m.contribute(routes).by(async (c) => {
		const known = await c.get(users);
		const gates = await c.get(logins);
		const recorded = await c.get(audit);
		const recordLogin = (
			request: HttpRequest,
			outcome: "succeeded" | "held" | "failed",
			subject?: string,
		) => {
			const source = determinedSource(request);
			declaredAudit(recorded, events).record(`login.${outcome}`, {
				...(subject === undefined ? {} : { subject }),
				attributes: { method: "password", ...(source === undefined ? {} : { source }) },
			});
		};
		const read = c.section;
		const window = {
			limit: read.attempts,
			ms: (read["window-seconds"] ?? read.window) * 1000,
		};
		const budgets = await c.get(lockouts);
		const windowMs = (read["account-window-seconds"] ?? read["account-window"]) * 1000;
		// Waits double from a second to the longest; no budget or hard limit ever holds one for good.
		const policy: LockoutPolicy = {
			threshold: c.section["account-attempts"],
			backoffMs: 1000,
			maxBackoffMs: (read["account-max-wait-seconds"] ?? read["account-max-wait"]) * 1000,
			budget: Number.MAX_SAFE_INTEGER,
			budgetWindowMs: windowMs,
			hardLimit: Number.MAX_SAFE_INTEGER,
			memoryMs: windowMs,
		};
		const problem = lockoutProblem(policy);
		if (problem) return c.refuse("login-password", `attempts per account: ${problem}`);
		const login = async (request: HttpRequest): Promise<HttpResponse> => {
			if (request.fields.repeated().length > 0) {
				return answer(400, { error: "repeated_parameter" });
			}
			const field = (name: string) => request.fields.single(name);
			const destination = field("redirect_to");
			// A JSON destination that is not a string is refused; null is none.
			const mistyped = request.mistyped?.has("redirect_to") && request.json?.redirect_to !== null;
			if (mistyped) return answer(400, { error: "invalid_redirect" });
			if (destination !== undefined && !gates.returnAllowed(destination)) {
				return answer(400, { error: "invalid_redirect" });
			}
			const username = field("username");
			const password = field("password");
			if (!username || !password) return answer(400, { error: "invalid_request" });
			const key = accountKey(username);
			const reserved = await budgets.reserve(accountAttempts, key, policy).catch((error) => {
				if (isUnavailable(error)) return undefined;
				throw error;
			});
			if (!reserved) return answer(503, { error: "service_unavailable" });
			if (reserved.kind === "held") {
				const seconds = Math.max(1, Math.ceil((reserved.retryAfterMs ?? windowMs) / 1000));
				return {
					...answer(429, { error: "too_many_attempts" }),
					headers: { ...noStore, "retry-after": String(seconds) },
				};
			}
			const verified = await known.verify(username, password).catch(async (error) => {
				// A guess never judged is handed back; the run goes on without it.
				if (isUnavailable(error))
					await budgets.abandoned(accountAttempts, key, policy, reserved.reservation);
				throw error;
			});
			// When the password was proved: the login's authentication time, whatever a gate holds after.
			const verifiedAt = c.clock.now();
			if (verified.kind !== "user") {
				recordLogin(request, "failed");
				return answer(401, { error: "invalid_credentials" });
			}
			await budgets.succeeded(accountAttempts, key, policy, reserved.reservation);
			// A gate that holds the login answers this once it lets the login through.
			const done = destination === undefined ? {} : { redirect_to: destination };
			const facts = {
				subject: verified.user.subject,
				amr: proves,
				authenticatedAt: verifiedAt,
				attributes: attributesOf(verified.user),
			};
			const outcome = await gates.login(request, facts, done);
			if (outcome.kind === "held") {
				recordLogin(request, "held", facts.subject);
				return answer(403, outcome.answer, outcome.cookies);
			}
			recordLogin(request, "succeeded", facts.subject);
			return answer(200, done, outcome.cookies);
		};
		return {
			method: "POST",
			path: "/session/login",
			takes: ["form", "json"],
			// The count comes after the CSRF check, before the handler judges the request: a malformed one counts too.
			uses: [use(csrfChecked), use(attemptsPerSource, { name: "login-password", window })],
			handle: async (request) => {
				try {
					return await login(request);
				} catch (error) {
					if (isUnavailable(error)) return answer(503, { error: "temporarily_unavailable" });
					throw error;
				}
			},
		};
	}),
]);
