import { type HttpRequest, type HttpResponse, jsonAnswer } from "@mod/http";
import type { BuildContext } from "@mod/kernel";
import { type Logins, logins } from "@mod/login-gates";
import { type PasskeyHolders, passkeyHolders } from "@mod/passkeys";
import { type Sessions, sessions } from "@mod/session";
import { type SubjectRevocation, subjectRevocation } from "@mod/subject-revocation";
import { type Recorded, recordedIn } from "../audited/audited.ts";
import { type Asserted, factsIn, type factsOver } from "../facts/facts.ts";
import type { Settings } from "../section.ts";

export interface OpeningParts {
	readonly holders: Pick<PasskeyHolders, "held">;
	readonly revocation: Pick<SubjectRevocation, "check">;
	readonly logins: Pick<Logins, "login">;
	readonly sessions: Pick<Sessions, "close">;
	readonly facts: ReturnType<typeof factsOver>;
	readonly recorded: Recorded;
}

const failed = { error: "passkey_login_failed" };

/**
 * Opens the session an assertion proved, through the gates, asking the revocation of its subject
 * since the challenge was made before the gates (step 1), before a hold is handed on (step 5) and
 * once opened (step 6).
 */
export function openingOver(p: OpeningParts) {
	return async (request: HttpRequest, asserted: Asserted, done: unknown): Promise<HttpResponse> => {
		const { subject, challengedAt } = asserted;
		const refuse = (reason: string) => {
			p.recorded.session(request, "refused", subject, reason);
			return jsonAnswer(401, failed);
		};
		// A revocation since the challenge was made, a reset's included, opens nothing.
		const revoked = async () => (await p.revocation.check(subject, challengedAt)) !== "valid";
		if (await revoked()) return refuse("revoked");
		const found = await p.facts(asserted);
		if (found.kind === "unanswerable") {
			return jsonAnswer(503, { error: "temporarily_unavailable" });
		}
		if (found.kind !== "facts") return refuse("unknown_user");
		// Settled with the witness before any gate: the mark of one who uses a passkey fills here.
		if (!(await p.holders.held(subject))) return refuse("unknown-credential");
		const outcome = await p.logins.login(request, found.facts, done);
		if (outcome.kind === "refused") return refuse("gate_refused");
		if (outcome.kind === "held") {
			// The transaction began before this: a revocation since the challenge hands nothing on.
			if (await revoked()) return refuse("revoked");
			p.recorded.session(request, "held", subject);
			return jsonAnswer(403, outcome.answer, { cookies: outcome.cookies });
		}
		// session-lifecycle compares with the opening, so a revocation since the challenge ends it here.
		if (await revoked()) {
			await p.sessions.close(outcome.session.id);
			return refuse("revoked");
		}
		p.recorded.session(request, "opened", subject);
		return jsonAnswer(200, done, { cookies: outcome.cookies });
	};
}

export type Opening = ReturnType<typeof openingOver>;

export const openingIn = async (c: BuildContext<Settings>) =>
	openingOver({
		holders: await c.get(passkeyHolders),
		revocation: await c.get(subjectRevocation),
		logins: await c.get(logins),
		sessions: await c.get(sessions),
		facts: await factsIn(c),
		recorded: await recordedIn(c),
	});
