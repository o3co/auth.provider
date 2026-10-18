import { type HttpRequest, site } from "@mod/http";
import { defineModule } from "@mod/kernel";
import { type LoginFacts, type Session, sessions } from "@mod/session";
import { urlSetting } from "@mod/url-setting";
import { z } from "zod";
import {
	amrSources,
	type LoginFrom,
	type LoginGate,
	type LoginOutcome,
	loginGates,
	logins,
	openedAfterHold,
	returnPaths,
} from "./contract.ts";

const section = z.strictObject({
	"return-targets": z
		.array(urlSetting({ schemes: ["https"], loopbackHttp: true }))
		.prefault([])
		.describe(
			"The https URLs (http only on a loopback host), matched as written, a login may return to besides the return paths modules contribute.",
		),
});

export default defineModule({ name: "login-gates", section, replicaSafe: true }, (m) => [
	m.provide(logins).by(async (c) => {
		const opening = await c.get(sessions);
		// By name in code units, not locale, so every host runs them alike. Names are keyed, never equal.
		const gates = (await c.collect(loginGates)).toSorted((a, b) => (a.name < b.name ? -1 : 1));
		const provable = new Set((await c.collect(amrSources)).flatMap((source) => source.amr));
		const targets = new Set(c.section["return-targets"]);
		const origin = (await c.get(site)).origin;
		const paths = new Set((await c.collect(returnPaths)).map((p) => p.path));
		const returnAllowed = (target: string) => {
			// The URL parser drops some of these silently; a target is judged as written.
			if (/[\s\p{Cc}]/u.test(target)) return false;
			if (targets.has(target)) return true;
			const url = URL.parse(target);
			if (!url || origin === undefined || target.includes("#")) return false;
			// Spelled from the public origin and the path itself: no userinfo, port or other origin.
			return paths.has(url.pathname) && target.startsWith(`${origin}${url.pathname}`);
		};
		const callers = new Map((await c.collect(openedAfterHold)).map((told) => [told.caller, told]));
		// Known only per call: a caller that contributed nothing is the caller's own mistake.
		const tellerOf = (from: LoginFrom | undefined) => {
			if (from === undefined) return undefined;
			const told = callers.get(from.caller);
			if (told === undefined) throw new TypeError("login-gates: no caller contributed this name");
			// The login stays open whatever the caller does with the news.
			return async (session: Session) => {
				try {
					await told.opened(session, from.carry);
				} catch (error) {
					const kind = error instanceof Error ? error.name : typeof error;
					c.log.error("login-gates.opened_failed", { caller: from.caller, kind });
				}
			};
		};
		const through = async (
			request: HttpRequest,
			facts: LoginFacts,
			pending: readonly LoginGate[],
			done: unknown = null,
			from?: LoginFrom,
		): Promise<LoginOutcome> => {
			for (const gate of pending) {
				const decision = await gate.hold(request, facts, done, from);
				if (decision.kind === "held") {
					const cookies = decision.cookies ?? [];
					return { kind: "held", gate: gate.name, answer: decision.answer, cookies };
				}
			}
			return { kind: "opened", ...(await opening.complete(request, facts)) };
		};
		return {
			achievable: (amr) => amr.every((name) => provable.has(name)),
			returnAllowed,
			login: async (request, facts, done, from) => {
				tellerOf(from);
				return through(request, facts, gates, done, from);
			},
			resume: async (request, facts, after, done, from) => {
				const heldAt = gates.findIndex((gate) => gate.name === after);
				if (heldAt === -1) throw new TypeError("login-gates: no gate has this name");
				const tell = tellerOf(from);
				if (from?.deadline !== undefined && c.clock.now() >= from.deadline)
					return { kind: "expired" };
				const outcome = await through(request, facts, gates.slice(heldAt + 1), done, from);
				if (outcome.kind === "opened") await tell?.(outcome.session);
				return outcome;
			},
		};
	}),
]);
