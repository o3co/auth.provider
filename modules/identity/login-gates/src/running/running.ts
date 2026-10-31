import type { HttpRequest } from "@mod/http";
import type { Clock, Log } from "@mod/kernel";
import type { LoginFacts, Session, Sessions } from "@mod/session";
import type { LoginFrom, LoginGate, LoginOutcome, Logins, OpenedAfterHold } from "../contract.ts";

/** A login through the gates in their order, and a held one resumed after the gate that held it. */
export function runningWith(parts: {
	readonly gates: readonly LoginGate[];
	readonly callers: ReadonlyMap<string, OpenedAfterHold>;
	readonly opening: Sessions;
	readonly clock: Clock;
	readonly log: Log;
}): Pick<Logins, "login" | "resume"> {
	const { gates, callers, opening, clock, log } = parts;
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
				log.error("login-gates.opened_failed", { caller: from.caller, kind });
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
			if (decision.kind === "refused") return { kind: "refused", gate: gate.name, cookies: [] };
			if (decision.kind === "held") {
				const cookies = decision.cookies ?? [];
				return { kind: "held", gate: gate.name, answer: decision.answer, cookies };
			}
		}
		return { kind: "opened", ...(await opening.complete(request, facts)) };
	};
	/** The gates before `heldAt` that are asked again on resume; one holding there is the gate's error. */
	const rechecked = async (
		request: HttpRequest,
		facts: LoginFacts,
		heldAt: number,
		done: unknown = null,
		from?: LoginFrom,
	): Promise<LoginOutcome | undefined> => {
		for (const gate of gates.slice(0, heldAt).filter((g) => g.rechecked)) {
			const decision = await gate.hold(request, facts, done, from);
			if (decision.kind === "refused") return { kind: "refused", gate: gate.name, cookies: [] };
			if (decision.kind === "held") {
				throw new TypeError("login-gates: a gate asked again on resume may only pass or refuse");
			}
		}
		return undefined;
	};
	return {
		login: async (request, facts, done, from) => {
			tellerOf(from);
			return through(request, facts, gates, done, from);
		},
		resume: async (request, facts, after, done, from) => {
			const heldAt = gates.findIndex((gate) => gate.name === after);
			if (heldAt === -1) throw new TypeError("login-gates: no gate has this name");
			const tell = tellerOf(from);
			if (from?.deadline !== undefined && clock.now() >= from.deadline) return { kind: "expired" };
			const outcome =
				(await rechecked(request, facts, heldAt, done, from)) ??
				(await through(request, facts, gates.slice(heldAt + 1), done, from));
			if (outcome.kind === "opened") await tell?.(outcome.session);
			return outcome;
		},
	};
}
