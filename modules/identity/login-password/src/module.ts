import { audit, declaredAudit } from "@mod/audit";
import { csrfChecked } from "@mod/csrf";
import { type HttpRequest, routes, use } from "@mod/http";
import { defineModule, isUnavailable, setting } from "@mod/kernel";
import { amrSources, logins } from "@mod/login-gates";
import { attemptsPerSource, type LockoutPolicy, lockoutProblem, lockouts } from "@mod/rate-limit";
import { determinedSource } from "@mod/request-source";
import { users } from "@mod/users";
import { z } from "zod";
import events from "./audit-events.ts";
import { answer, loginWith, proves } from "./login.ts";

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
		.describe(
			"How long an identifier's run of failed attempts is remembered, from 1m to 1d, and no shorter than `account-max-wait`.",
		),
	"account-max-wait": setting
		.duration("s")
		.pipe(z.number().int().min(1).max(3600))
		.prefault("5m")
		.describe(
			"The longest an identifier waits between attempts, from 1s to 1h and no longer than `account-window`: the wait doubles to it, never locking out.",
		),
});

export default defineModule(
	{ name: "login-password", replicaSafe: true, section, takes: [audit, logins, lockouts, users] },
	(m) => [
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
			const window = { limit: c.section.attempts, ms: c.section.window * 1000 };
			const budgets = await c.get(lockouts);
			const windowMs = c.section["account-window"] * 1000;
			// Waits double from a second to the longest; no budget or hard limit ever holds one for good.
			const policy: LockoutPolicy = {
				threshold: c.section["account-attempts"],
				backoffMs: 1000,
				maxBackoffMs: c.section["account-max-wait"] * 1000,
				budget: Number.MAX_SAFE_INTEGER,
				budgetWindowMs: windowMs,
				hardLimit: Number.MAX_SAFE_INTEGER,
				memoryMs: windowMs,
			};
			const problem = lockoutProblem(policy);
			if (problem) return c.refuse("login-password", `attempts per account: ${problem}`);
			const login = loginWith({ known, gates, budgets, policy, windowMs, recordLogin, log: c.log });
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
	],
);
